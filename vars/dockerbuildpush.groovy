def call(Map params) {
    def uniqueLabel = "docker-build-push-${UUID.randomUUID().toString()}"  

    podTemplate(
        label: uniqueLabel,
        containers: [
            containerTemplate(name: 'git', image: 'alpine/git:latest', command: 'sleep', args: '999999', ttyEnabled: true, alwaysPullImage: true),
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
                CUSTOM_REGISTRY = params.CUSTOM_REGISTRY ?: 'docker.io'
                DOCKERFILE_LOCATION = params.DOCKERFILE_LOCATION ?: '.'
            }

            // ✅ Extract Git Parameters
            String GIT_URL = params.GIT_URL ?: params['params']?.GIT_URL ?: ''
            String GIT_BRANCH = params.GIT_BRANCH ?: params['params']?.GIT_BRANCH ?: ''
            String GIT_CREDENTIALS = params.GIT_CREDENTIALS ?: params['params']?.GIT_CREDENTIALS ?: ''

            if (!GIT_URL || !GIT_BRANCH) {
                error "GIT_URL or GIT_BRANCH is not set!"
            }

            // ✅ Improved Git Clone Logic (Supports Public and Private Repos)
            stage('Git Clone') {
                container('git') {
                    script {
                        withEnv(["GIT_URL=${GIT_URL}", "GIT_BRANCH=${GIT_BRANCH}"]) {
                            try {
                                if (GIT_CREDENTIALS?.trim()) {   // Private repo handling
                                    withCredentials([usernamePassword(credentialsId: GIT_CREDENTIALS, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                                        echo "Cloning private repository from $GIT_URL - Branch: $GIT_BRANCH"
                                        sh '''
                                            git --version
                                            git config --global --add safe.directory $PWD
                                            git clone --depth=1 --branch $GIT_BRANCH https://${GIT_USERNAME}:${GIT_PASSWORD}@${GIT_URL.replace('https://', '')} .
                                        '''
                                    }
                                } else {   // Public repo handling
                                    echo "Cloning public repository from $GIT_URL - Branch: $GIT_BRANCH"
                                    sh '''
                                        git --version
                                        git config --global --add safe.directory $PWD
                                        git clone --depth=1 --branch $GIT_BRANCH $GIT_URL .
                                    '''
                                }
                            } catch (Exception e) {
                                error "Cloning repository failed: ${e.getMessage()}"
                            }
                        }
                    }
                }
            }

            // ✅ Trivy Repo Scan
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

            // ✅ Docker Build Stage
            stage('Build Docker Image') {
                container('docker') {
                    script {
                        try {
                            echo "Building Docker image..."
                            sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ${DOCKERFILE_LOCATION}"
                        } catch (Exception e) {
                            error "Docker build failed: ${e.getMessage()}"
                        }
                    }
                }
            }

            // ✅ Trivy Image Scan
            stage('Trivy Image Scan') {
                container('trivy') {
                    script {
                        try {
                            sh "mkdir -p /root/.cache/trivy/db"
                            sh "trivy image --download-db-only --timeout 15m --debug"
                            
                            echo "Scanning Docker image with Trivy..."
                            sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --timeout 15m -f json -o trivy-image-scan.json"
                            sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --timeout 15m -f table -o trivy-image-scan.txt"

                            recordIssues(
                                enabledForFailure: true,
                                tool: trivy(pattern: 'trivy-image-scan.json', id: 'trivy-image', name: 'Image Scan Report')
                            )

                            archiveArtifacts artifacts: "trivy-image-scan.json", fingerprint: true
                            archiveArtifacts artifacts: "trivy-image-scan.txt", fingerprint: true
                        } catch (Exception e) {
                            error "Trivy image scan failed: ${e.getMessage()}"
                        }
                    }
                }
            }

            // ✅ Docker Push Stage
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
