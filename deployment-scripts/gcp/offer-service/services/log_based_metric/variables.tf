/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


variable "environment" {
  description = "Assigned environment name to group related resources."
  type        = string
}

variable "request_fail_alert_threshold" {
  description = "Threashold for request failure rate alert_policy"
  type        = number
  default     = 0.1
}

# iSPIRT/DEPA: the request-failure AlertPolicy uses a PromQL query over
# workload_googleapis_com:request_count / request_failed_count. GCP validates
# that PromQL at create time, and those metric descriptors only exist AFTER the
# workload has served real getBids traffic. On a fresh test_mode deploy (no
# traffic) creation fails with "PromQL metric(s) are invalid". Default off so
# the deploy is green; flip to true once the servers have served traffic.
variable "enable_request_failure_alert" {
  description = "Create the request-failure-rate AlertPolicy (requires workload request metrics to already exist)."
  type        = bool
  default     = false
}
