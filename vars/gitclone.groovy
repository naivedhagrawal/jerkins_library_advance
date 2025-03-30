// /home/naivedh/repo/jerkins_library_advance/vars/gitclone.groovy
def call(Map params = [:]) {
    String GIT_URL = ''
    String GIT_BRANCH = ''
    String GIT_CREDENTIALS = ''

    def nestedParams = params['params'] ?: params

    GIT_URL = nestedParams['GIT_URL'] ?: ''
    GIT_BRANCH = nestedParams['GIT_BRANCH'] ?: ''
    GIT_CREDENTIALS = nestedParams['GIT_CREDENTIALS'] ?: ''

    try {
        if (GIT_CREDENTIALS?.trim()) {
            echo "Cloning private repo: ${GIT_URL} with credentials: ${GIT_CREDENTIALS}"
            withCredentials([usernamePassword(credentialsId: GIT_CREDENTIALS, usernameVariable: 'GIT_USERNAME', passwordVariable: 'GIT_PASSWORD')]) {
                withEnv(["GIT_URL=${GIT_URL}", "GIT_BRANCH=${GIT_BRANCH}"]) {
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
