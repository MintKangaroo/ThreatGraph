# STIX 2.1 수집

`STIXBundleImporter`는 STIX 2.1 JSON bundle을 검증하고 원본 객체를 workspace별로 보존하며
ThreatGraph 엔터티와 관계로 변환합니다. `STIXBundleExporter`는 보존 객체를 다시 bundle로
직렬화합니다.

지원 Indicator 패턴은 domain-name, IPv4/IPv6, URL, file hash입니다. identity, process, file,
vulnerability, threat-actor, malware, campaign, attack-pattern 등도 매핑합니다. `uses`는
대상이 attack-pattern일 때만 `uses_technique`로 변환됩니다. ATT&CK attack-pattern은
`external_references`의 `T####`/`T####.###` 값을 canonical key로 사용하고 tactic,
platform, revoked/deprecated 정보를 보존합니다. 공식 ATT&CK bundle의 `x_mitre_*` 사용자
속성을 허용하되 ThreatGraph의 strict entity 모델로 들어오기 전에 정규화합니다.
변환 관계마다 Evidence 노드를 먼저 생성하고 source, 시간, confidence, evidence_id,
workspace_id를 기록합니다.

지원하지 않는 패턴·객체는 `IngestReport.skipped`에 기록합니다. 원본 STIX ID에서 결정적
UUID를 만들기 때문에 같은 workspace 재수집이 중복 노드를 만들지 않습니다. IOC는
canonical key로 중복 제거하며 필요할 때 민감 값을 마스킹합니다.

`TAXIIBundleSource.iter_bundles()`는 문자열, UTF-8 bytes 또는 JSON mapping을 비동기적으로
반환하는 연결 경계입니다. 실제 TAXII 인증·페이지네이션 클라이언트는 이 프로토콜에 어댑터로
연결하며 importer의 최대 bundle 객체 수 기본값은 10,000개입니다.

Sigma 규칙의 `attack.t####`와 `attack.t####.###` 태그는 같은 canonical
`AttackTechnique` identity와 `uses_technique` 관계로 변환할 수 있습니다. 자세한 규칙은
[ATT&CK mapping](attack.md)을 참고하십시오.
