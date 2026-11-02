import http from "k6/http";
import { check, sleep } from "k6";
import { Trend } from "k6/metrics";

const BASE = __ENV.ATLAS_API_URL || "http://127.0.0.1:8000/api/v1";
const EMAIL = __ENV.ATLAS_EMAIL || "soc@atlas.demo";
const PASSWORD = __ENV.ATLAS_PASSWORD || "AtlasDemo!2026";

const overviewLatency = new Trend("atlas_overview_latency", true);

export const options = {
  scenarios: {
    read_paths: {
      executor: "ramping-vus",
      startVUs: 5,
      stages: [
        { duration: "30s", target: 20 },
        { duration: "1m", target: 40 },
        { duration: "30s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<800"],
    atlas_overview_latency: ["p(95)<1000"],
  },
};

export function setup() {
  const login = http.post(
    `${BASE}/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(login, { "login succeeded": (response) => response.status === 200 });
  return { token: login.json("access_token") };
}

export default function (data) {
  const headers = { Authorization: `Bearer ${data.token}` };
  const paths = [
    "/dashboard/overview",
    "/findings?page_size=25",
    "/assets?page_size=25",
    "/microservices?page_size=25",
    "/sbom?page_size=25",
    "/risks?page_size=25",
    "/notifications?page_size=10",
  ];
  const path = paths[Math.floor(Math.random() * paths.length)];
  const response = http.get(`${BASE}${path}`, { headers });
  check(response, { "status 200": (result) => result.status === 200 });
  if (path === "/dashboard/overview") overviewLatency.add(response.timings.duration);
  sleep(Math.random() * 2);
}
