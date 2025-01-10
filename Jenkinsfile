pipeline {
    agent any

    environment {
        DOCKER_IMAGE_TAG = "datespot-${BUILD_NUMBER}"  // 고유한 Docker 이미지 태그
        // ECR_REPO = "240317130487.dkr.ecr.ap-northeast-2.amazonaws.com/datespot"
        // AWS_REGION = "ap-northeast-2"
        TMP_WORKSPACE = "/tmp/jenkins_workspace"  // 임시 작업 디렉터리
        // AWS_ACCESS_KEY_ID = credentials('s3 Credentials')
        // AWS_SECRET_ACCESS_KEY = credentials('s3 Credentials')
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
            }
        }
        // stage("Debug Environment") {
        //     steps {
        //         sh '''
        //             echo "AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
        //             echo "AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
        //             echo "AWS_REGION: $AWS_REGION"
        //         '''
        //     }
        // }

        // docker build -t ${ECR_REPO}:${DOCKER_IMAGE_TAG} -f Dockerfile .
        stage('Build Docker Image') {
            steps {
                sh '''
                    echo "Building Docker Image with tag: ${DOCKER_IMAGE_TAG}"
                    docker build -t $test:${DOCKER_IMAGE_TAG} -f Dockerfile .
                    echo "Tagging image as latest"
                '''
            }
        }
      stage("Deploy") {
        steps {
            sh '''
                echo "Deploying Docker Image with tag: ${DOCKER_IMAGE_TAG}"
                DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG} \
                docker-compose -f docker-compose.yml up -d
            '''
            }
        }
    }
}
