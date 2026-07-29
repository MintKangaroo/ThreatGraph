# ThreatGraph 인수인계

현재 브랜치: `feat/stix-ingestion` (원격 동기화 대상 동일 브랜치)

초기 로드맵 10개 마일스톤이 모두 구현되었습니다. Graph schema/repository, STIX 2.1,
IOC 정규화, MITRE ATT&CK·Sigma Technique identity, 시간창 기반 상관분석, neighborhood·
shortest path·incident graph API, Evidence-grounded narrative, React 조사 대시보드,
AI-SOC Dashboard·AutoPentest AI·SentinelFlow export 계약이 포함됩니다.

대시보드는 demo fallback과 실제 workspace 모드를 지원합니다. 라이브 모드에서는
correlation 내러티브를 표시하고 노드 더블클릭으로 2-hop neighborhood를 확장합니다.
세부사항은 [README.md](README.md), [docs/api.md](docs/api.md),
[docs/analysis.md](docs/analysis.md), [docs/attack.md](docs/attack.md)를 참고합니다.

검증 기준:

- Python 3.12: Ruff lint/format, strict mypy, pytest **96개**, statement coverage **100%**
- React: Vitest **12개**, TypeScript/Vite production build
- Docker Compose configuration validation 및 서비스 health/readiness

배포 시 남은 운영 설정은 identity layer의 workspace authorization, 실제 TAXII credential,
downstream transport와 retry 정책, 운영 데이터 규모의 부하 테스트입니다. 이는
vendor-neutral core 밖의 배포 책임이며, export finding UUID를 idempotency key로
사용합니다.

브랜치 규칙: `main`은 안정 릴리스, `develop`은 통합, 기능은 `feat/<기능명>`, 수정은
`fix/<문제명>`, 문서는 `docs/<문서명>`입니다. 모든 관계는 같은 workspace의 Evidence를
요구하며, query API에는 limit와 traversal/time-window 상한을 유지합니다.
