# PostgreSQL 배포 가이드

이 디렉토리는 Kubernetes 환경에서 kustomize를 사용하여 PostgreSQL을 배포하기 위한 설정 파일들을 포함합니다.

## 파일 구조

- `kustomization.yaml`: kustomize 설정 파일
- `namespace.yaml`: identity 네임스페이스 생성
- `postgresql-configmap.yaml`: 데이터베이스 설정
- `postgresql-pvc.yaml`: 영구 저장소 요청
- `postgresql-deployment.yaml`: PostgreSQL 배포 설정
- `postgresql-service.yaml`: PostgreSQL 서비스 설정

## 배포 방법

### 1. kustomize를 사용한 배포

배포 전에 외부 Secret 관리 시스템으로 `identity` 네임스페이스에
`postgresql-secret`을 생성해야 합니다. Secret에는 다음 키가 있어야 합니다.

- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_DB`

이 저장소에는 데이터베이스 계정이나 비밀번호를 포함한 Secret 매니페스트를
두지 않습니다. 운영 환경에서는 External Secrets Operator, 클라우드 Secret
Manager 연동 등 조직의 비밀 관리 방식을 사용하세요.

```bash
kubectl apply -k deploy/
```

### 2. 배포 확인

```bash
# 네임스페이스 확인
kubectl get namespaces

# 파드 상태 확인
kubectl get pods -n identity

# 서비스 확인
kubectl get services -n identity

# PVC 확인
kubectl get pvc -n identity
```

### 3. Identity 애플리케이션 설정

Identity 애플리케이션은 다음 환경변수를 필수로 요구합니다.

- `JWT_PUBLIC_KEY`: access token 서명에 사용할 최소 32바이트 비밀키
- `JWT_PRIVATE_KEY`: refresh token 서명에 사용할 최소 32바이트 비밀키
- `DATABASE_URL`: PostgreSQL 연결 문자열

세 값은 애플리케이션 Deployment에서 외부 Secret의 키로 주입하세요. 키는
예를 들어 `openssl rand -base64 32`로 생성하세요. 현재 애플리케이션은
단일 활성 키만 지원하므로 JWT 키를 교체하면 기존 토큰이 즉시 무효화됩니다.
무중단 키 교체가 필요하면 다중 키 검증을 먼저 도입한 뒤 교체하고, 그렇지
않으면 배포 시점과 토큰 폐기 정책을 조율해야 합니다.

### 4. 로컬에서 포트 포워딩

```bash
kubectl port-forward -n identity service/postgresql-service 5432:5432
```

## 보안 고려사항

저장소에는 JWT 키, 데이터베이스 연결 문자열, 데이터베이스 계정 또는
비밀번호를 기록하지 않습니다. Base64 인코딩은 암호화가 아니므로 Secret
매니페스트를 저장소에 커밋하거나 환경변수를 Deployment에 평문으로 넣지
마세요.

과거 커밋 `4ce0b58`과 `b1a1120`에는 이전 데이터베이스 자격증명과 JWT
키가 포함되어 있으므로 실제 사용 가능성이 있다면 이미 노출된 것으로
간주해야 합니다. 외부 Secret 관리 시스템에서 데이터베이스 자격증명과
JWT 키를 즉시 새 값으로 교체하고, 기존 JWT를 폐기하는 운영 절차를
진행하세요.

Git 히스토리에서 비밀값을 제거하는 작업은 별도의 승인된 운영 작업입니다.
히스토리 재작성, 강제 푸시, 포크·미러·캐시 정리는 이 변경에 포함하지
않았으며, 저장소 관리자와 배포·보안 담당자의 조율 후 수행해야 합니다.
