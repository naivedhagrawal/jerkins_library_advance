def call(Map params) {
    def imageName = params.IMAGE_NAME
    def imageTag = params.IMAGE_TAG ?: 'latest'
    def dockerHubUsername = params.DOCKER_HUB_USERNAME
    def dockerCredentialsId = params.DOCKER_CREDENTIALS
    def gitCredentialsId = params.GIT_CREDENTIALS  // Changed variable name
    def customRegistry = params.CUSTOM_REGISTRY ?: 'docker.io'
    def dockerfileLocation = params.DOCKERFILE_LOCATION ?: '.'
    String gitURL = ''
    String gitBranchName = ''
     if (params instanceof Map) {
        def nestedParams = params['params'] ?: params
        gitURL = nestedParams['GIT_URL'] ?: ''
        gitBranchName = nestedParams['GIT_BRANCH'] ?: 'main'
    } else {
        error "params is not a Map."
    }
    if (!imageName || !dockerHubUsername || !dockerCredentialsId || !gitURL) {
        error "Missing required parameters: IMAGE_NAME, DOCKER_HUB_USERNAME, DOCKER_CREDENTIALS, and GIT_URL are mandatory."
    }
     if (!gitURL || !gitBranchName) {
        error "GIT_URL or GIT_BRANCH is not set!"
    }  
    def uniqueLabel = "docker-build-push-${UUID.randomUUID().toString()}"
    podTemplate(
        label: uniqueLabel,
        containers: [
            containerTemplate(name: 'alpine-git', image: 'alpine/git:latest', command: 'sleep', args: '999999', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'trivy', image: 'aquasec/trivy:latest', command: 'sleep', args: '999999', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'docker', image: 'docker:latest', command: 'sleep', args: '99d', ttyEnabled: true, alwaysPullImage: true),
            containerTemplate(name: 'docker-daemon', image: 'docker:dind', command: 'dockerd', privileged: true, ttyEnabled: true, alwaysPullImage: true)
        ],
        volumes: [
            emptyDirVolume(mountPath: '/var/run', memory: false),
            emptyDirVolume(mountPath: '/root/.cache/trivy', memory: false)
        ]
    ) {
        node(uniqueLabel) {
            environment {
                IMAGE_NAME = imageName
                IMAGE_TAG = imageTag
                DOCKER_HUB_USERNAME = dockerHubUsername
                DOCKER_CREDENTIALS = dockerCredentialsId
                GIT_CREDENTIALS = gitCredentialsId  // Used variable
                CUSTOM_REGISTRY = customRegistry
                DOCKERFILE_LOCATION = dockerfileLocation
                GIT_URL = gitURL
            }
            stage('Clone Git Repository') {
                container('alpine-git') {
                    script {
                        try {
                            if (gitCredentialsId?.trim()) {  // Use gitCredentialsId
                                echo "Cloning private repo: ${GIT_URL} with credentials: ${gitCredentialsId}"
                                withCredentials([usernamePassword(credentialsId: gitCredentialsId, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                                    withEnv(["GIT_URL=${gitURL}", "GIT_BRANCH=${gitBranchName}"]) {
                                        sh '''
                                            echo "Cloning repository from $GIT_URL - Branch: $GIT_BRANCH"
                                            git --version
                                            git config --global --add safe.directory $PWD
                                            git clone --depth=1 --branch $GIT_BRANCH https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_URL.replace('https://', '')} .
                                        '''
                                    }
                                }
                            } else {
                                echo "Cloning public repo: ${GIT_URL}"
                                withEnv(["GIT_URL=${gitURL}", "GIT_BRANCH=${gitBranchName}"]) {
                                    sh '''
                                        echo "Cloning repository from $GIT_URL - Branch: $GIT_BRANCH"
                                        git --version
                                        git config --global --add safe.directory $PWD
                                        git clone --depth=1 --branch $GIT_BRANCH $GIT_URL .
                                    '''
                                }
                            }
                        } catch (Exception e) {
                            error "Cloning repository failed: ${e.getMessage()}"
                        }
                    }
                }
            }
            stage('Trivy Repo Scan') {
                container('trivy') {
                    script {
                        try {
                            echo "Scanning Git repo with Trivy..."
                            sh "trivy fs . --timeout 15m -f json -o trivy-repo-scan.json"
                            sh "trivy fs . --timeout 15m -f table -o trivy-repo-scan.txt"
                            recordIssues(
                                enabledForFailure: true,
                                tool: trivy(pattern: 'trivy-repo-scan.json', id: 'trivy-repo', name: 'Repo Scan Report')
                            )
                            archiveArtifacts artifacts: "trivy-repo-scan.json", fingerprint: true
                            archiveArtifacts artifacts: "trivy-repo-scan.txt", fingerprint: true
                        } catch (Exception e) {
                            error "Trivy repo scan failed: ${e.getMessage()}"
                        }
                    }
                }
            }
            stage('Build Docker Image') {
                container('docker') {
                    script {
                        try {
                            echo "Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG} from ${DOCKERFILE_LOCATION}"
                            sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ${DOCKERFILE_LOCATION}"
                        } catch (Exception e) {
                            error "Build Docker Image failed: ${e.getMessage()}"
                        }
                    }
                }
            }
            stage('Trivy Image Scan') {
                container('trivy') {
                    script {
                        try {
                            sh "mkdir -p /root/.cache/trivy/db"
                            sh "trivy image --download-db-only --timeout 15m --debug"
                            echo "Scanning image ${IMAGE_NAME}:${IMAGE_TAG} with Trivy..."
                            sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --timeout 15m -f json -o trivy-report.json"
                            sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --timeout 15m -f table -o trivy-report.txt"
                            recordIssues(
                                enabledForFailure: true,
                                tool: trivy(pattern: "trivy-report.json", id: "trivy-json", name: "Image Scan Report")
                            )
                            archiveArtifacts artifacts: "trivy-report.json", fingerprint: true
                            archiveArtifacts artifacts: "trivy-report.txt", fingerprint: true
                        } catch (Exception e) {
                            error "Trivy image scan failed: ${e.getMessage()}"
                        }
                    }
                }
            }
            stage('Push Docker Image') {
                container('docker') {
                    script {
                        try {
                            withCredentials([usernamePassword(credentialsId: DOCKER_CREDENTIALS, usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                                echo "Logging into Docker registry: ${CUSTOM_REGISTRY} as user: ${USERNAME}"
                                sh '''
                                    echo \$PASSWORD | docker login ${CUSTOM_REGISTRY} -u \$USERNAME --password-stdin
                                    docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                                    docker push ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                                '''
                            }
                        } catch (Exception e) {
                            error "Push Docker Image failed: ${e.getMessage()}"
                        }
                    }
                }
            }
        }
    }
}
