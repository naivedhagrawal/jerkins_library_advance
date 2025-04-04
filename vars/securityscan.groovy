// /home/naivedh/repo/jerkins_library_advance/vars/securityscan.groovy
def call(Map params = [:]) {
    String GIT_URL = ''
    String GIT_BRANCH = ''
    String GIT_CREDENTIALS = ''
    boolean IS_DOCKER_BUILD_PUSH = false

    if (params instanceof Map) {
        def nestedParams = params['params'] ?: params
        GIT_URL = nestedParams['GIT_URL'] ?: ''
        GIT_BRANCH = nestedParams['GIT_BRANCH'] ?: ''
        GIT_CREDENTIALS = nestedParams['GIT_CREDENTIALS'] ?: ''
        IS_DOCKER_BUILD_PUSH = nestedParams['IS_DOCKER_BUILD_PUSH'] ?: false
    } else {
        error "params is not a Map."
    }
    if (!GIT_URL || !GIT_BRANCH) {
        error "GIT_URL or GIT_BRANCH is not set!"
    }

    // Define the security scan logic
    def runSecurityScans = {
        // 🚀 Parallel Security Scans
        stage('Run Security Scans') {
            parallel(
                "Gitleaks Secret Scan": {
                    stage('Gitleaks Secret Scan') {
                        container('gitleak') {
                            sh '''
                                gitleaks version
                                gitleaks detect --source=. --report-path=gitleaks-report.sarif --report-format sarif --exit-code=0          
                                gitleaks detect --source=. --report-path=gitleaks-report.csv --report-format csv --exit-code=0
                            '''
                            recordIssues(
                                enabledForFailure: true,
                                tools: [sarif(pattern: "gitleaks-report.sarif", id: "Secrets", name: "Secret Scanning Report", icon: "symbol-key")],

                                qualityGates: [
                                    [threshold: 5, type: 'TOTAL', unstable: true],
                                    [threshold: 2, type: 'NEW', unstable: true]
                                ]
                            )
                        }
                    }
                },
                "OWASP Dependency Check": {
                    stage('OWASP Dependency Check') {
                        container('owasp') {
                            sh '''
                                mkdir -p reports
                                echo "Running OWASP Dependency Check..."
                                /usr/share/dependency-check/bin/dependency-check.sh --scan . \
                                    --format "SARIF" \
                                    --format "JSON" \
                                    --format "CSV" \
                                    --format "XML" \
                                    --exclude "**/*.zip" \
                                    --out "reports/"
                                
                                mv reports/dependency-check-report.sarif owasp-report.sarif
                                mv reports/dependency-check-report.json owasp-report.json
                                mv reports/dependency-check-report.csv owasp-report.csv
                                mv reports/dependency-check-report.xml owasp-report.xml
                            '''
                            recordIssues(
                                enabledForFailure: true,
                                tools: [owaspDependencyCheck(pattern: "owasp-report.json", id: "Vulnerability", name: "Dependency Check Report")],

                                qualityGates: [
                                    [threshold: 20, type: 'TOTAL', unstable: true],
                                    [threshold: 8, type: 'NEW', unstable: true]
                                ]
                            )
                        }
                    }
                },
                "Semgrep Analysis": {
                    stage('Semgrep Analysis') {
                        container('semgrep') {
                            sh '''
                                semgrep --version
                                semgrep --config=auto --sarif --output semgrep-report.sarif .
                            '''
                            recordIssues(
                                enabledForFailure: true,
                                tools: [sarif(pattern: "semgrep-report.sarif", id: "StaticAnalysis", name: "Static Analysis Report", icon: "symbol-error")],

                                qualityGates: [
                                    [threshold: 15, type: 'TOTAL', unstable: true],
                                    [threshold: 5, type: 'NEW', unstable: true]
                                ]
                            )
                        }
                    }
                },
                "Checkov IaC Scan": {
                    stage('Checkov IaC Scan') {
                        container('checkov') {
                            sh '''
                                checkov --directory . -o sarif -o csv || true
                            '''
                            recordIssues(
                                enabledForFailure: true,
                                tools: [sarif(pattern: "results.sarif", id: "IaC", name: "IaC Vulnerability Report", icon: "symbol-cloud")],

                                qualityGates: [
                                    [threshold: 10, type: 'TOTAL', unstable: true],
                                    [threshold: 4, type: 'NEW', unstable: true]
                                ]
                            )
                        }
                    }
                }
            )
        }

        stage('Archive Results') {
            archiveArtifacts artifacts: "gitleaks-report.sarif, gitleaks-report.csv, semgrep-report.sarif, results.sarif, *iac.csv, owasp-report.sarif, owasp-report.json, owasp-report.csv, owasp-report.xml"
        }
    }

    // If security scan is called directly
    if (!IS_DOCKER_BUILD_PUSH) {
        def uniqueLabel = "security-scan-${UUID.randomUUID().toString()}"
        podTemplate(
            label: uniqueLabel,
            containers: [
                containerTemplate(name: 'gitleak', image: 'zricethezav/gitleaks:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
                containerTemplate(name: 'owasp', image: 'owasp/dependency-check-action:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
                containerTemplate(name: 'semgrep', image: 'returntocorp/semgrep:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
                containerTemplate(name: 'checkov', image: 'bridgecrew/checkov:latest', command: 'cat', ttyEnabled: true, alwaysPullImage: true),
            ],
            envVars: [
                envVar(key: 'GIT_SSL_NO_VERIFY', value: 'false')
            ],
            showRawYaml: false
        ) {
            node(uniqueLabel) {
                stage('Clone Git Repository') {
                    gitclone(params: [GIT_URL: GIT_URL, GIT_BRANCH: GIT_BRANCH, GIT_CREDENTIALS: GIT_CREDENTIALS])
                }
                runSecurityScans()
            }
        }
    } else {
        // If security scan is called from dockerbuildpush
        stage('Clone Git Repository') {
            gitclone(params: [GIT_URL: GIT_URL, GIT_BRANCH: GIT_BRANCH, GIT_CREDENTIALS: GIT_CREDENTIALS])
        }
        container('gitleak'){
            runSecurityScans()
        }
    }
}