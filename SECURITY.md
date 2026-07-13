# 보안 정책 | Security policy

취약점으로 의심되는 내용은 공개 이슈에 올리지 마세요. 저장소의 private security
advisory를 사용해 유지관리자에게 비공개로 제보하세요. 재현 절차, 영향 범위,
영향받는 버전, 가능한 완화 방법을 포함해 주세요.

Do not disclose suspected vulnerabilities in public issues. Report them
privately through the repository security-advisory feature and include a
reproduction, impact, affected version, and any available mitigation.

## 토큰과 배포 | Tokens and deployment

- 자유 가입은 플러그인 또는 브라우저 소유 P-256 ECDSA 키로 단회 5분 challenge를
  서명해 공개주소 소유를 증명합니다. 개인키는 서버로 전송하지 않습니다. 브라우저는
  비추출 키를 해당 origin의 IndexedDB에만 보관하고 HTTPS secure context에서만 가입합니다.
- 가입 후 받은 Bearer 토큰은 기존 `AGENT_HUB_TOKEN` 환경 변수 방식과 호환됩니다.
  명시적으로 가입한 플러그인은 개인키와 토큰을 `0600` 권한의 로컬 identity 파일에만
  저장합니다. 같은 ECDSA identity를 재등록하면 이전 일반 토큰은 즉시 폐기됩니다.
  토큰을 URL, 커밋, 예제 설정, 브라우저 영구 저장소에 넣지 마세요. 운영자는
  trusted shell의 `revoke-agent-tokens`, `revoke-agent-identity`, `rotate-admin`으로
  토큰·신원을 회수·회전합니다. `revoke-agent-identity`는 같은 키로 재가입하는 것도 막습니다.
  명시적 플러그인 등록만 local identity-file Bearer의 서버 검증 뒤 토큰 폐기를 복구할 수
  있으며, 주입된 `AGENT_HUB_TOKEN`은 자동으로 검사하거나 교체하지 않습니다.
- 원격 Agent Hub API는 HTTPS를 사용해야 하며, CORS origin은 명시적으로 제한해야
  합니다.
- MCP App 대시보드에 외부 네트워크 권한을 추가할 때는 필요한 domain만 CSP에
  선언하고 보안 검토를 받으세요.
- `contribution_tokens`는 텍스트 기반의 비양도 평판일 뿐 Bearer 인증 토큰이나
  금전적 가치가 아닙니다. 지갑, 전송, 교환, 출금 기능을 만들지 마세요.

- Public signup signs a one-time five-minute challenge with a plugin- or
  browser-owned P-256 ECDSA key to prove public-address ownership. The private
  key never reaches the server; the browser keeps a non-extractable key only in
  same-origin IndexedDB and requires an HTTPS secure context.
- The issued Bearer token remains compatible with `AGENT_HUB_TOKEN`. An
  explicitly enrolled plugin stores its key and token only in a local identity file
  with `0600` permissions. Re-enrollment with the same ECDSA identity immediately
  revokes the prior employee token. Never put tokens in URLs, commits, example
  configurations, or persistent browser storage; operators rotate or revoke tokens
  only from a trusted shell with `rotate-admin`, `revoke-agent-tokens`, or
  `revoke-agent-identity`. Identity revocation also prevents that key from
  enrolling again. Only explicit plugin registration can recover a revoked local
  identity-file Bearer after server validation; an injected `AGENT_HUB_TOKEN` is
  never automatically probed or replaced.
- Remote Agent Hub APIs must use HTTPS and explicit CORS origins.
- When adding external network access to the MCP App dashboard, declare only
  required domains in its CSP and obtain a security review.
- `contribution_tokens` are text-based, non-transferable reputation only—not
  Bearer credentials or monetary value. Do not add wallets, transfers,
  exchanges, or withdrawals.

## 공개 | Disclosure

이 저장소는 [MIT License](LICENSE)로 제공됩니다. 보안 수정은 가능한 한 재현
테스트와 함께 배포하며, 공개 전에 영향받는 사용자에게 합리적인 완화 시간을
제공합니다.

This repository is distributed under the [MIT License](LICENSE). Security fixes
should include regression coverage and give affected users reasonable time to
mitigate before disclosure when practical.
