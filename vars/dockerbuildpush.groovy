def call(Map params) {
    def nestedParams = params['params'] ?: params
    def gitURL = nestedParams['GIT_URL'] ?: ''
    def gitBranchName = nestedParams['GIT_BRANCH'] ?: 'main'
    def imageName = nestedParams.IMAGE_NAME
    def imageTag = nestedParams.IMAGE_TAG ?: 'latest'
    def dockerHubUsername = nestedParams.DOCKER_HUB_USERNAME
    def dockerCredentialsId = nestedParams.DOCKER_CREDENTIALS
    def gitCredentialsId = nestedParams.GIT_CREDENTIALS ?: ''
    def customRegistry = nestedParams.CUSTOM_REGISTRY ?: 'docker.io'
    def dockerfileLocation = nestedParams.DOCKERFILE_LOCATION ?: '.'

    if (!imageName || !dockerHubUsername || !dockerCredentialsId || !gitURL) {
        error "Missing required parameters: IMAGE_NAME, DOCKER_HUB_USERNAME, DOCKER_CREDENTIALS, and GIT_URL are mandatory."
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
            withEnv([
                "IMAGE_NAME=${imageName}",
                "IMAGE_TAG=${imageTag}",
                "DOCKER_HUB_USERNAME=${dockerHubUsername}",
                "DOCKER_CREDENTIALS=${dockerCredentialsId}",
                "GIT_CREDENTIALS=${gitCredentialsId}",
                "CUSTOM_REGISTRY=${customRegistry}",
                "DOCKERFILE_LOCATION=${dockerfileLocation}",
                "GIT_URL=${gitURL}"
            ]) {
                stage('Clone Git Repository') {
                    container('alpine-git') {
                        script {
                            try {
                                if (gitCredentialsId?.trim()) {
                                    echo "Cloning private repo: ${gitURL} with credentials: ${gitCredentialsId}"
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
                                    echo "Cloning public repo: ${gitURL}"
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
                                echo "Building Docker image: ${imageName}:${imageTag} from ${dockerfileLocation}"
                                sh "docker build -t ${imageName}:${imageTag} ${dockerfileLocation}"
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
                                echo "Scanning image ${imageName}:${imageTag} with Trivy..."
                                sh "trivy image ${imageName}:${imageTag} --timeout 15m -f json -o trivy-report.json"
                                sh "trivy image ${imageName}:${imageTag} --timeout 15m -f table -o trivy-report.txt"
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
                                withCredentials([usernamePassword(credentialsId: dockerCredentialsId, usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                                    echo "Logging into Docker registry: ${customRegistry} as user: ${USERNAME}"
                                    sh '''
                                        echo \$PASSWORD | docker login ${customRegistry} -u \$USERNAME --password-stdin
                                        docker tag ${imageName}:${imageTag} ${customRegistry}/${imageName}:${imageTag}
                                        docker push ${customRegistry}/${imageName}:${imageTag}
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
}
