# ThreatGraph 세션 인수인계

최종 갱신: **2026-07-30 (Asia/Seoul)**

## 다음 세션 시작점

- GitHub 기본 브랜치: `main`
- 안정 릴리스: [`v0.1.0`](https://github.com/MintKangaroo/ThreatGraph/releases/tag/v0.1.0)
- 릴리스 커밋: `40e0739b2622728b9aaedb49597a29425ac5e1e6`
- MVP Core: **100% 완료 (초기 로드맵 10/10)**
- 열린 GitHub PR: 없음
- 필수 미구현 TODO/FIXME: 없음

새 세션은 기존 기능 브랜치에서 계속하지 말고 최신 `main`에서 시작합니다.

```bash
git fetch origin --tags
git switch main
git pull --ff-only origin main
git switch develop
git pull --ff-only origin develop
git status --short
```

새 작업은 목적에 맞는 `feat/<이름>`, `fix/<이름>`, `docs/<이름>` 브랜치를
`develop`에서 생성합니다. 검증된 릴리스만 `develop`에서 `main`으로 승격합니다.

## 완료된 범위

1. FastAPI, PostgreSQL, Neo4j, Redis/Celery, React/Vite, Docker Compose 기반
2. 17개 graph entity, 13개 relationship, Evidence 필수 관계, workspace 격리
3. STIX 2.1 bundle 검증·보존·import/export와 TAXII async source boundary
4. IP/domain/URL/hash canonicalization, deduplication, 민감 IOC masking
5. MITRE ATT&CK technique/sub-technique 및 Sigma `attack.t####` tag mapping
6. 시간창, 공통 IOC/asset/identity, ATT&CK chain 결정적 상관분석
7. pagination, time range, neighborhood, incident graph, shortest path API
8. claim별 relationship/Evidence ID와 gap을 제공하는 grounded narrative
9. 검색·필터·critical path·timeline·export·live/demo·2-hop 확장 대시보드
10. AI-SOC Dashboard, AutoPentest AI, SentinelFlow versioned export envelope

대시보드 스크린샷과 전체 흐름은 [README](README.md)에 포함되어 있습니다.

## 마지막 검증 결과

| 영역 | 결과 |
| --- | --- |
| Python | Ruff format/lint, strict mypy 통과 |
| Backend | pytest **96개**, statement coverage **100%** |
| Frontend | Vitest **12개**, TypeScript/Vite production build 통과 |
| Compose | 구성 검증, PostgreSQL/Neo4j/Redis readiness 통과 |
| Graph integration | schema 초기화, API health/readiness 통과 |
| GitHub Actions | backend/web/compose/graph 네 job 모두 성공 |

최종 `main` CI:
<https://github.com/MintKangaroo/ThreatGraph/actions/runs/30441213640>

GitHub Actions는 `actions/checkout`, `actions/setup-python`,
`actions/setup-node`의 `v7` runtime을 사용합니다.

## 로컬 실행과 확인

최초 실행 시에만 환경 파일을 만듭니다. 기존 `.env`가 있으면 덮어쓰지 않습니다.

```bash
test -f .env || cp .env.example .env
docker compose up --build --wait
```

확인 주소:

- Dashboard: <http://localhost:5173>
- API/OpenAPI: <http://localhost:8000/docs>
- Neo4j Browser: <http://localhost:7474>

```bash
curl --fail http://127.0.0.1:8000/api/v1/health/live
curl --fail http://127.0.0.1:8000/api/v1/health/ready
```

일반 종료는 데이터를 보존합니다.

```bash
docker compose down
```

`docker compose down --volumes`는 로컬 PostgreSQL/Neo4j/Redis 데이터를 삭제하므로
명시적으로 초기화가 필요할 때만 사용합니다.

전체 로컬 품질 검사는 다음 명령으로 실행합니다.

```bash
make check
```

## 코드 위치

| 경로 | 책임 |
| --- | --- |
| `src/threatgraph/graph/` | typed graph model, Neo4j schema/repository/query |
| `src/threatgraph/stix/` | STIX mapping, preservation, import/export, TAXII protocol |
| `src/threatgraph/ioc/` | IOC normalization, identity, masking |
| `src/threatgraph/attack.py` | ATT&CK/STIX/Sigma technique identity |
| `src/threatgraph/correlation.py` | bounded deterministic correlation |
| `src/threatgraph/narrative.py` | Evidence-grounded claims and gaps |
| `src/threatgraph/platforms.py` | downstream integration envelope |
| `src/threatgraph/api/` | health, graph, analysis, export HTTP boundary |
| `web/src/` | React investigation dashboard |
| `tests/unit/` | backend behavior and 100% coverage suite |
| `docs/` | architecture, schema, API, analysis, integration documentation |

## 다음 개발 사이클

현재 저장소 자체의 필수 미완성 기능은 없습니다. 다음 작업은 배포 환경이 결정된 뒤
진행하는 운영 통합입니다.

우선순위:

1. **Identity/authorization:** 배포 IdP를 선택하고 모든 workspace route 전에
   caller-to-workspace 권한을 검증합니다.
2. **Production transports:** 실제 TAXII 인증·pagination source와 downstream
   HTTP/queue delivery, retry, dead-letter 정책을 연결합니다.
3. **Scale validation:** 운영 데이터 크기의 Neo4j dataset으로 latency, query limit,
   correlation truncation을 측정합니다.
4. **Operations:** metrics, traces, structured audit logs, backup/restore, retention 정책을
   배포 스택에 연결합니다.

세부 우선순위와 완료 기준은 [Roadmap](docs/roadmap.md)의 Post-MVP 섹션을 따릅니다.

## 반드시 유지할 불변조건

- 모든 graph read/write는 `workspace_id`를 요구합니다.
- relationship source, target, Evidence는 같은 workspace에 있어야 합니다.
- relationship에는 source, first/last seen, confidence, Evidence ID가 필요합니다.
- caller properties가 identity/workspace/evidence/time reserved field를 덮어쓰면 안 됩니다.
- graph pagination, traversal depth, correlation time window 상한을 제거하지 않습니다.
- sensitive entity는 HTTP 응답 전에 마스킹합니다.
- grounded narrative와 platform export는 relationship/Evidence ID를 보존합니다.
- 테스트 추가 시 backend statement coverage 100%와 strict typing을 유지합니다.

## 설계 결정

- 상관분석과 내러티브는 동일 입력에 동일 결과를 내는 결정적 규칙을 사용합니다.
- 근거가 없는 문장은 생성하지 않고 `gaps`로 노출합니다.
- vendor credential과 transport 정책은 core domain에서 분리합니다.
- export finding UUID는 downstream idempotency key로 사용할 수 있습니다.

## GitHub 기록

- [PR #1 — MVP 기능 통합](https://github.com/MintKangaroo/ThreatGraph/pull/1)
- [PR #2 — v0.1.0 main 릴리스](https://github.com/MintKangaroo/ThreatGraph/pull/2)
- [Release v0.1.0](https://github.com/MintKangaroo/ThreatGraph/releases/tag/v0.1.0)

다음 세션 종료 시 이 파일의 날짜, 기준 커밋, 검증 수치, 다음 작업과 GitHub 링크를
다시 갱신합니다.
