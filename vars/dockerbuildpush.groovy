def call(Map params = [:]) {
    String GIT_URL = ''
    String GIT_BRANCH = ''
    String IMAGE_NAME = ''
    String IMAGE_TAG = ''
    String DOCKER_HUB_USERNAME = ''
    String DOCKER_CREDENTIALS = ''
    String GIT_CREDENTIALS = ''
    String CUSTOM_REGISTRY = ''
    String DOCKERFILE_LOCATION = '.'

    def nestedParams = params['params'] ?: params

    GIT_URL = nestedParams['GIT_URL'] ?: ''
    GIT_BRANCH = nestedParams['GIT_BRANCH'] ?: ''
    IMAGE_NAME = nestedParams['IMAGE_NAME'] ?: ''
    IMAGE_TAG = nestedParams['IMAGE_TAG'] ?: 'latest'
    DOCKER_HUB_USERNAME = nestedParams['DOCKER_HUB_USERNAME'] ?: ''
    DOCKER_CREDENTIALS = nestedParams['DOCKER_CREDENTIALS'] ?: ''
    GIT_CREDENTIALS = nestedParams['GIT_CREDENTIALS'] ?: ''
    CUSTOM_REGISTRY = nestedParams['CUSTOM_REGISTRY'] ?: 'docker.io'
    DOCKERFILE_LOCATION = nestedParams['DOCKERFILE_LOCATION'] ?: '.'

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
        ],
        showRawYaml: false

    ) {
        node(uniqueLabel) {
                stage('Clone Git Repository') {
                    container('alpine-git') {
                        script {
                            try {
                                if (GIT_CREDENTIALS?.trim()) {
                                    echo "Cloning private repo: ${GIT_URL} with credentials: ${GIT_CREDENTIALS}"
                                    withCredentials([usernamePassword(credentialsId: GIT_CREDENTIALS, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                                        withEnv(["GIT_URL=${GIT_URL}", "GIT_BRANCH=${GIT_BRANCH}"]) {
                                            sh "echo "Cloning repository from $GIT_URL - Branch: $GIT_BRANCH""
                                            sh "git --version"
                                            sh "git config --global --add safe.directory $PWD"
                                            sh "git clone --depth=1 --branch $GIT_BRANCH https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_URL.replace('https://', '')} ."
                                        } 
                                    }
                                } else {
                                    withEnv(["GIT_URL=${GIT_URL}", "GIT_BRANCH=${GIT_BRANCH}"]) {
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
                                    tool: trivy(pattern: 'trivy-repo-scan.json', id: 'trivy-repo', name: 'Repo Scan Report'),

                                    qualityGates: [
                                        [threshold: 5, type: 'TOTAL', unstable: true],
                                        [threshold: 2, type: 'NEW', unstable: true]
                                    ]
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
                                    tool: trivy(pattern: "trivy-report.json", id: "trivy-json", name: "Image Scan Report"),

                                    qualityGates: [
                                        [threshold: 5, type: 'TOTAL', unstable: true],
                                        [threshold: 2, type: 'NEW', unstable: true]
                                    ]
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
                                if (!IMAGE_NAME || !IMAGE_TAG) {
                                    error "IMAGE_NAME or IMAGE_TAG is empty. Cannot proceed with Docker push."
                                }

                                withCredentials([usernamePassword(credentialsId: DOCKER_CREDENTIALS, usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                                    echo "Logging into Docker registry: ${CUSTOM_REGISTRY} as user: ${USERNAME}"
                                    sh "echo $PASSWORD | docker login ${CUSTOM_REGISTRY} -u $USERNAME --password-stdin"

                                    // Use different tag format for Docker Hub
                                    if ("${CUSTOM_REGISTRY}" == "docker.io") {
                                        sh "docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
                                        sh "docker push ${USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}"
                                    } else {
                                        sh "docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
                                        sh "docker push ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
                                    }
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
