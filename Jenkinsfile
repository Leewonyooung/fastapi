pipeline {
    agent any
    environment {
        DOCKER_IMAGE_TAG = "test-${BUILD_NUMBER}"
        WORKSPACE_DIR = "${env.WORKSPACE}"
    }
    stages {
        stage("Init") {
            steps {
                script {
                    gv = load "script.groovy"
                }
            }
        }
        stage("Checkout") {
            steps {
                checkout scm
                sh 'echo "Checked out source code"'
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                    def dockerfilePath = "${WORKSPACE_DIR}/Dockerfile"
                    def composeFilePath = "${WORKSPACE_DIR}/docker-compose.yml"
                    if (!fileExists(dockerfilePath)) {
                        error "Dockerfile not found at ${dockerfilePath}"
                    }
                    if (!fileExists(composeFilePath)) {
                        error "docker-compose.yml not found at ${composeFilePath}"
                    }
                    sh """
                        echo "Building Docker Image with tag: ${DOCKER_IMAGE_TAG}"
                        docker build -t test:${DOCKER_IMAGE_TAG} -f ${dockerfilePath} .
                    """
                }
            }
        }

        stage("Deploy") {
            steps {
                sh """
                    echo "Deploying Docker Image with tag: ${DOCKER_IMAGE_TAG}"
                    DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG} \
                    docker-compose -f docker-compose.yml up -d
                """
            }
        }
    }
}
