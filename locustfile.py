from locust import HttpUser, task, between

class FastAPITestUser(HttpUser):
    wait_time = between(1, 2)  # 요청 간 대기 시간 (1~2초)

    @task
    def test_with_redis(self):
        # self.client.get("/place/select_redis")  # Redis 없이 테스트
        self.client.get("clinic/select_clinic")  # Redis 없이 테스트
        # self.client.get("clinic/select_clinic_noredis")  # Redis 없이 테스트

    # @task
    # def test_no_redis(self):
    #     self.client.get("/clinic/select_clinic_noredis")  # Redis 없이 테스트
    #     # self.client.get("/place/select")  # Redis 사용 테스트