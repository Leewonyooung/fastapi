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
        stage('Setup Git Safe Directory') {
            steps {
                sh 'git config --global --add safe.directory /var/jenkins_home/workspace/test_pipe'
            }
        }
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/Leewonyooung/fastapi'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker Image with tag: test-${BUILD_NUMBER}"
                    docker build -t test:test-${BUILD_NUMBER} -f dockerfile .
                '''
            }
        }
        stage('Deploy') {
            steps {
                sh '''
                    echo "Deploying application..."
                '''
            }
        }
    }
}
