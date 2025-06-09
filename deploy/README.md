# PostgreSQL 배포 가이드

이 디렉토리는 Kubernetes 환경에서 kustomize를 사용하여 PostgreSQL을 배포하기 위한 설정 파일들을 포함합니다.

## 파일 구조

- `kustomization.yaml`: kustomize 설정 파일
- `namespace.yaml`: identity 네임스페이스 생성
- `postgresql-secret.yaml`: 데이터베이스 인증 정보
- `postgresql-configmap.yaml`: 데이터베이스 설정
- `postgresql-pvc.yaml`: 영구 저장소 요청
- `postgresql-deployment.yaml`: PostgreSQL 배포 설정
- `postgresql-service.yaml`: PostgreSQL 서비스 설정

## 배포 방법

### 1. kustomize를 사용한 배포
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

### 3. 데이터베이스 연결 정보
- **호스트**: postgresql-service.identity.svc.cluster.local
- **포트**: 5432
- **사용자**: postgres
- **비밀번호**: postgres123
- **데이터베이스**: identity

### 4. 로컬에서 포트 포워딩
```bash
kubectl port-forward -n identity service/postgresql-service 5432:5432
```

## 보안 고려사항

현재 Secret에 저장된 패스워드는 예시용입니다. 프로덕션 환경에서는 다음과 같이 변경하세요:

1. 강력한 패스워드 생성
2. Base64 인코딩하여 postgresql-secret.yaml 업데이트
3. 또는 외부 Secret 관리 도구 사용
