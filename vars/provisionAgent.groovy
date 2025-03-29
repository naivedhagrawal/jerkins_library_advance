def provisionAgent(Map config = [:]) {
    podTemplate(label: config.label, containers: config.containers) {
        node(config.label) {
            stage(config.stageName) {
                container(config.containerName) {
                    sh config.command
                }
            }
        }
    }
}
