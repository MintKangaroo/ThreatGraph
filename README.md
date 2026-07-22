# ThreatGraph

ThreatGraph는 AI-SOC Dashboard, AutoPentest AI, SentinelFlow가 공통으로 사용하는 그래프
분석 계층입니다. 증거를 보존하고 워크스페이스 간 데이터를 격리하면서 자산, 이벤트,
IOC, 취약점, 위협 행위자, MITRE ATT&CK 기법(Technique)을 연결하고 상관분석하는 위협
인텔리전스 플랫폼을 목표로 합니다.

> 현재 상태: Graph Schema 및 Repository 계층 구축 단계입니다. STIX 데이터 수집,
> 상관분석, 시각화, AI 설명 기능은 각각의 후속 단계에서 구현합니다.

## 기반 서비스

- 생존 상태(liveness) 및 종속 서비스 준비 상태(readiness) 엔드포인트를 제공하는
  FastAPI 서비스
- 메타데이터 저장소인 PostgreSQL과 그래프 저장소인 Neo4j
- 17개 위협 인텔리전스 엔터티와 13개 Evidence 기반 관계 스키마
- workspace 격리와 idempotent entity upsert를 적용한 Neo4j Repository
- Redis 기반 Celery 워커 실행 환경
- React 및 Vite 기반 웹 기본 화면
- 영구 서비스 볼륨을 포함한 Docker Compose 개발 환경
- Python 및 웹 품질 검사를 수행하는 CI

## 빠른 시작

전체 로컬 환경은 Docker Compose를 사용해 실행합니다.

```bash
cp .env.example .env
docker compose up --build
```

`graph-init` 서비스가 API와 worker보다 먼저 Neo4j constraint 및 index를 idempotent하게
설치합니다. 로컬 Python 환경에서는 `make graph-schema`로 같은 작업을 직접 실행할 수
있습니다.

서비스가 시작되면 다음 주소로 접속할 수 있습니다.

- 웹 화면: <http://localhost:5173>
- API 문서: <http://localhost:8000/docs>
- Neo4j Browser: <http://localhost:7474>

개발 데이터는 이름이 지정된 Docker 볼륨에 저장됩니다. 서비스는
`docker compose down`으로 종료할 수 있습니다. 로컬 데이터까지 삭제하려는 경우에만
`--volumes` 옵션을 추가하십시오.

`.env.example`의 인증 정보는 격리된 로컬 개발 환경 전용입니다. 공유 환경이나 개발
이외의 환경에서는 모든 비밀번호를 반드시 교체해야 합니다. 기본적으로 인프라 포트는
루프백 인터페이스에만 바인딩됩니다.

## 상태 확인 엔드포인트

- `GET /api/v1/health/live`: API 프로세스가 요청을 처리할 수 있는지 확인합니다.
- `GET /api/v1/health/ready`: 제한 시간 안에 PostgreSQL, Neo4j, Redis 연결 상태를
  확인합니다.

준비 상태 검사에 실패하면 구성요소별 `up` 또는 `down` 상태만 반환합니다. 연결 정보와
내부 오류는 외부에 노출하지 않습니다.

## 로컬 품질 검사

컨테이너 외부에서 개발하려면 Python 3.12와 Node.js 20 이상이 필요합니다.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
make install web-install
make check
```

Python 테스트만 실행하려면 `make test`, 웹 테스트만 실행하려면 `make web-test`를
사용합니다.

## 그래프 스키마

모든 entity는 `workspace_id`와 type별 identity key로 식별됩니다. 동일 workspace에서
동일한 identity key를 다시 저장하면 새 node를 무제한 생성하지 않고 기존 node를
갱신합니다.

모든 relationship은 다음 속성을 필수로 가집니다.

- `source`
- `first_seen`, `last_seen`
- `confidence`
- `evidence_id`
- `workspace_id`

Repository는 source entity, target entity, Evidence가 모두 같은 workspace에 있을 때만
relationship을 생성합니다. 지원하는 전체 schema와 저장 규칙은
[그래프 스키마 문서](docs/graph-schema.md)를 참고하십시오.

## 아직 구현하지 않은 범위

현재 단계에는 다음 기능이 포함되지 않습니다.

- STIX/TAXII 가져오기 기능과 IOC 정규화 파이프라인
- MITRE ATT&CK 및 Sigma 매핑
- 시간 기반 이벤트 상관분석과 그래프 조회 API
- Cytoscape.js 기반 그래프 탐색기
- AI 기반 인시던트 설명과 외부 플랫폼 어댑터

대상 스캔이나 공격 행위도 구현하지 않습니다. 자세한 내용은
[그래프 스키마](docs/graph-schema.md), [아키텍처](docs/architecture.md),
[로드맵](docs/roadmap.md),
[보안 정책](SECURITY.md)을 참고하십시오.

## 기여

개발 및 검증 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하십시오. 이 프로젝트는
MIT License로 배포됩니다.
