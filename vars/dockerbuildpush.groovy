/* @Library('advance') _
dockerbuildpush(
    IMAGE_NAME: 'owasp-dependency',
    IMAGE_TAG: 'latest',
    DOCKER_HUB_USERNAME: 'naivedh',
    DOCKER_CREDENTIALS: 'docker_hub_up',
    GIT_REPO: 'https://github.com/naivedh/sample-repo.git',
    GIT_BRANCH: 'main',
    GIT_CREDENTIALS: '',
    CUSTOM_REGISTRY: '',
    DOCKERFILE_LOCATION: '.'
)*/

def call(Map params) {
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
                IMAGE_NAME = "${params.IMAGE_NAME}"
                IMAGE_TAG = "${params.IMAGE_TAG}"
                DOCKER_HUB_USERNAME = "${params.DOCKER_HUB_USERNAME}"
                DOCKER_CREDENTIALS = "${params.DOCKER_CREDENTIALS}"
                GIT_REPO = "${params.GIT_REPO}"
                GIT_BRANCH = "${params.GIT_BRANCH}"
                GIT_CREDENTIALS = "${params.GIT_CREDENTIALS}"
                CUSTOM_REGISTRY = params.CUSTOM_REGISTRY ?: 'docker.io'
                DOCKERFILE_LOCATION = params.DOCKERFILE_LOCATION ?: '.'
            }

            stage('Clone Git Repository') {
                container('alpine-git') {
                    script {
                        try {
                            if (GIT_CREDENTIALS) {
                                withCredentials([usernamePassword(credentialsId: GIT_CREDENTIALS, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                                    echo "Cloning private repo: ${GIT_REPO}"
                                    sh "git clone -b ${GIT_BRANCH} https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_REPO.replace('https://', '')} ."
                                }
                            } else {
                                echo "Cloning public repo: ${GIT_REPO}"
                                sh "git clone -b ${GIT_BRANCH} ${GIT_REPO} ."
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
                            echo "Building Docker image..."
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
                            echo "Scanning image with Trivy..."
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
                                echo "Logging into Docker registry: ${CUSTOM_REGISTRY}"
                                sh """
                                    echo \$PASSWORD | docker login ${CUSTOM_REGISTRY} -u \$USERNAME --password-stdin
                                    docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                                    docker push ${CUSTOM_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                                """
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
