pipeline {
    agent any

    environment {
        DOCKER_IMAGE_TAG = "test-${BUILD_NUMBER}"  // 고유한 Docker 이미지 태그
        WORKSPACE_DIR = "${env.WORKSPACE}"        // Jenkins 워크스페이스 경로
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

                    // Dockerfile과 docker-compose.yml 파일 확인
                    if (!fileExists(dockerfilePath)) {
                        error "Dockerfile not found at ${dockerfilePath}"
                    }
                    if (!fileExists(composeFilePath)) {
                        error "docker-compose.yml not found at ${composeFilePath}"
                    }

                    // Docker 이미지 빌드
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
