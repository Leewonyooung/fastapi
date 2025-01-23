from locust import HttpUser, task, between

class FastAPITestUser(HttpUser):
    wait_time = between(1, 2)  # 요청 간 대기 시간 (1~2초)

    @task
    def test_with_redis(self):
        self.client.get("/available/available_clinic")  # Redis 없이 테스트

    @task
    def test_no_redis(self):
        self.client.get("/available/available_clinic_noredis")  # Redis 사용 테스트