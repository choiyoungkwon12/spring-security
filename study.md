# Spring-security (인프런)

# 스프링 시큐리티 기본 api & Filter의 이해

## UsernamePasswordAuthenticationFilter

![img.png](image/img.png)

사용자가 인증을 요청함.

- UsernamePasswordAuthenticationFilter가 요청정보를 받아서 url을 확인(default : /login)해서 매칭되는지 검사함.
    - 만약 일치하지 않으면 다음 필터로 체이닝하고 일치한다면 실제 인증처리(Authentication)함.
    - 일치한 경우 Authentication 객체를 만들어서 사용자가 요청할때 작성한 username + password 정보를 인증객체에 저장해서 실제 인증객체를 맡기는 역할을 한다.
    - 인증처리를 하기전에 UsernamePasswordAuthenticationFilter가 하는일이고, 인증 객체를 생성 후 인증처리를 맡기는 데 하는 객체가 Authenticationmanager(인증 관리자)가 한다.
    - Authenticationmanager는 내부적으로 AuthenticationProvider라는 객체들을 가지고 있고 인증을 위임하게 된다. (실제로 인증하는 객체)
    - 인증 실패 시 AuthenticationException 발생. 인증성공 시 Authentiacation 객체 만듬.
        - Authentiacation(User + Authorites) 를 반환
    - 반환 받은 Authentiacation객체를 SecurityContext라는 인증객체를 저장하는 저장소에 저장.
    - 나중에는 SecurityContext가 세션에 저장되게 되고 전형적으로 사용자가 SecurityContext안에서 Authentication를 참조할 수 있도록 처리를 해줌.
    - 성공 시 SuccessHandler에서 작업 치리

  FIlterChainProxy (이후 아키텍처 부분에서 더 자세하게 공부) : 로그인을 했을 때, 체이닝된 많은 필터들을 거치게 되는데 이 필터들을 관리하는 빈(객체)이다.

- 스프링 시큐리티를 초기화 했을 때 생성되는 기본적인 필터와 사용자가 WebSecrityConfigurerAdapter를 상속받아서 오버라이딩 했을 때 api에 맞는 필터가 생성되고 커스텀을 추가할 수 있다.
  
## 인증 API - Logout

![img_1.png](image/img_1.png)

```
// http.logout() : 로그아웃 기능이 작동함.

http. logout()                   // 로그아웃 처리
		.logoutUrl("/logout")        // 로그아웃 처리 url
		.logoutSuccessUrl("/login")  // 로그아웃 성공 후 이동페이지
    .deleteCookies("JSESSIONID","remeber-me") // 로그아웃 후 쿠키 삭제
    .addLogoutHandler(logoutHandler()) // 로그아웃 핸들러
    .logoutSuccessHandler(logoutSuccessHandler()) // 로그아웃 성공 후 핸들러
```


## LogoutFilter

![img_2.png](image/img_2.png)

사용자가 로그아웃 요청(post)을 하면 LogoutFilter가 받는다.
- antPathRequestMatcher(/logout)이 url이 매칭 되는지 검사 후 일치하지 않으면 다음 필터로 위임
- 일치하면 인증정보를 담고있는 객체인 SecurityContext에서 Authentication(인증) 객체를 받아온다.
- LogoutFilter가 가지고 있는 핸들러중 SecurityContextLogoutHandler 클래스가 세션무효화, 쿠키삭제, SecurityContextHolder.clearContext()로 securityContext 삭제를 합니다.
- 원칙적으로는 로그아웃 시 post여야 하지만 SecurityContextLogoutHandler 을 이용해서 get방식으로 로그아웃 처리가능.
- 이렇게 LogoutFilter의 수행이 정상적으로 종료가 되면 SimpleUrlLogoutSuccessHandler를 호출해서 로그인페이지로 이동하도록 한다.

# 인증 API - Remember Me 인증

1. 세션이 만료되고 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
2. Remember-me 쿠키에 대한 http 요청을 확인 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검즈오디면 사용자는 로그인된다.
3. 사용자 라이프 사이클
  - 인증 성공 (Remember-Me 쿠키 설정)
  - 인증 실패 (쿠키가 존재하면 쿠키 무효화)
  - 로그아웃(쿠키가 존재하면 쿠키 무효화

![img_3.png](image/img_3.png)

## RemembermeAuthenticationFilter

![img_4.png](image/img_4.png)

RemembermeAuthenticationFilter는 브라우저가 종료되어서 세션을 사용하지 못하는 경우, 세션 만료가 된 경우 세션을 활성화 되지 않아서 인증객체를 securirt context에서 찾지 못하는 경우 사용자의 인증을 유지하기 위해서 RemembermeAuthenticationFilter가 인증을 시도하고 사용자의 인증을 받게 하여 서버의 인증을 유지해서 접근을 가능하도록 한다.

조건 1. Authentication 객체가 null이 아니어야 함.

조건 2. 사용자가 최초의 form인증을 받을 당시 remember-me 기능을 사용자가 활성화하여 remeberme 쿠키를 서버로부터 발급 받은 경우여야한다.

흐름.

1. 사용자는 세션이 만료된 상태고, 최초 로그인시 remember-me 기능 활성화함.
2. 그러면 RemembermeAuthenticationFilter가 동작함.
3. RememberMeServices는 인터페이스로 TokenBasedRememberMeservices, PersistentTokenBasedRememberMeServices가 구현체이다.
- TokenBasedRememberMeservices - 메모리에서 저장한 토큰과 사용자가 가지고 있는 토큰을 비교하는 방식 (기본적으로 14일 토큰 만료시간을 가짐)
- PersistentTokenBasedRememberMeServices - 토큰을 디비에 저장하고 클라이언트의 토큰과 비교하는 방식
4token cookie 추출(remember-me)
- 없으면 다음 필터 이동
- 있으면 토큰 decode
  - 정상아닐경우 exception
5. 토큰값이 정상일 경우 서버의 토큰과 일치하는지 판단.
- 없으면 exception
6. 토큰에 포함된 정보중 user 계정이 존재하는지 판단.
- 없으면 exception
7. 있으면 새로운 authentication 객체 생성
8. AuthenticationManager에게 인증객체 전달 후 인증처리 완료

# AnonymousAuthenticationFilter

![img_5.png](image/img_5.png)

- 일반적으로 익명 사용자는 null로 처리할 수 있는데 AnonymousAuthenticationFilter에서는 null이 아닌 AnonymousAuthenticationToken(익명 사용자 인증 객체)을 만들어서 securityContext안에 저장한다.
- 요청이 일어나고 필터체인의 순서에 의해 앞에 작업이 처리된 후 AnonymousAuthenticationFilter에서 처리할 차례가 오면 Authentication이 있는지 확인 후 있으면(이미 인증된 사용자) 다음 필터로 넘어가고 없으면 AnonymousAuthenticationToken을 만들어서 저장한다.
- 그래서 null값으로 구분하는 것인 아닌 isAnonymous(), isAuthentication() 으로 구분해서 사용한다.
- 인증객체를 생성했더라도 세션에 따로 저장하지 않는다.

AbsctractSecurityInterceptor : 맨 마지막에 인가처리를 하는 보안 필터

- 현재 사용자가 접근하고자 하는 자원에 접근이 가능한지 아닌지 인가 처리를 한다.
- 해당 처리 과정에서 SecurityContextHolder.getContext().getAuthentication() == null 로 검사 후 null 이면 예외를 발생시킨다.
- 그래서 스프링 시큐리티는 Authentication을 곳곳에서 확인하는데 여기서도 확인한다.
- 그래서 익명 사용자도 인증객체를 만들어서 인증된 사용자, 익명 사용자 구분용으로 만든다.


# 동시 세션 제어, 세션 고정 보호, 세션 정책

![img_1.png](image/img_7.png)

**동시세션 제어**는 동일한 계정으로 인증을 받을때 생성되는 세션 해당 갯수가 허용 갯수를 초과 되었을 때, 어떻게 세션을 초과하지 않고 유지하는지에 대한 제어를 말함 (2가지)

1. 이전 사용자 세션 만료
  1. 말 그대로 이전 사용자의 세션을 만료시키는 방식
  2. 그림에서 왼쪽으로 만약 세션 허용 갯수가 1개일때, 1번이 먼저 세션을 생성하고, 2번이 이후에 세션을 생성하면 1번 사용자의 세션이 만료된다.
  3. 그래서 다시 1번 사용자가 서버의 자원에 접근할 때 확인 후 세션을 만료시킨다.
2. 현재 사용자 인증 실패
  1. 말 그대로 세션 생성 허용갯수가 초과되면 이후 사용자 로그인에 실패하게 된다.


### 동시세션제어 API 사용법

![img_1.png](image/img_6.png)

invalidSessionUrl과 expiredUrl 둘다 사용한 경우 invalidSessionUrl이 더 우선시 되어 적용된다.


### 세션 고정 보호

![img_1.png](image/img_8.png)

**세션 고정 공격이란** 공격자가 먼저 서버에 접속해서 session 값을 가진 쿠키를 받고 사용자에게 공격자 쿠리를 사용하도록 합니다.

이후 사용자가 공격자 세션쿠키로 로그인을 시도 후 성공하면 공격자도 같은 세션쿠키를 가지고 있기 때문에 서버에 접근해서 같은 세션을 공유해서 사용자 정보를 탈취할 수 있습니다.

이를 방지하기 위해 스프링 시큐리티에서 사용하는 방법으로 사용자가 공격자가 심어놓은 쿠키로 인증을 하더라도 매번 서버에서 세션과 쿠키를 생성해서 제공한다.

그러면 공격자의 쿠키는 사용자가 인증 성공한 쿠키와 다르므로 공격을 할 수 없게 된다.

## 세션 고정 보호 API

![img_1.png](image/img_9.png)

changeSessonId 는 서블릿 3.1 이후에서 기본값으로 사용됨.

migrateSession은 서블리 3.1 이하에서 기본값으로 사용됨.

changeSessonId와 migrateSession는 이전의 세션 속성이나 정보를 이어서 사용가능하지만 newSession은 불가능하다.

none은 공격자에게 무방비 상태가 됨.

# 세션 정책

![img_1.png](image/img_10.png)

세션 생성 정책

jwt와 같이 세션을 전혀 사용하지 않을때는 stateless 방식으로 정책을 설정 할 수 있다.

# 세션 제어 필터 : SessionManagementFilter, ConcurrentSessionFilter

![img_1.png](image/img_11.png)

# 세션 제어 필터 : SessionManagementFilter, ConcurrentSessionFilter

![img_1.png](image/img_12.png)

ConcurrentSessionFilter는 SessionManagementFilter와 연계하여 동시적 세션 제어를 한다.

![img_1.png](image/img_13.png)

매 요청 마다 session.isExpired == true로 세션 만료 여부 체크한다.

![img_1.png](image/img_14.png)

1. 사용자가 이미 세션을 가지고 있는 계정으로 인증했는데 최대 세션 허용갯수가 초과된 경우 세션 제어 정책에 따라 제어를 하게되는데(sessionManagementFilter) 여기서는 이전 사용자 세션만료 정책에 대한 그림임.
2. 새로운 사용자가 인증을 하면 session.expireNow()로 이전 사용자의 세션이 만료가 되고 이전 사용자가 만약 다시 한번 요청을 보내서 서버에 접근을 한다면 세션이 만료되었는지 확인(ConcurrentSessionFilter) (session.isExpired) 후 오류 페이지를 응답하고 이전 사용자가 가지고 있는 세션 만료시킨다.


**인증부터 각각의 필터의 전반적인 처리과정 ( 최대 세션 허용갯수 1개 가정)**

![img_1.png](image/img_15.png)

사용자1이 로그인 시도.

- usernamePasswordAuthenticationFilter가 받는데 해당 필터는 가장 먼저 ConcurrentSessionControlAuthenticationStrategy(동시적 세션 제어함)를 호출하게 된다.
  - 해당 계정으로 인증한 세션의 갯수가 몇개인지 확인
- 두번째는 ChangeSessionIdAuthenticationStrategy가 세션 고정 보호를 하게된다.(session.changeSessionId())
- 세번째는 RegisterSessionAuthenticationStrategy를 호출해서 사용자의 세션을 등록하고 저장하는 역할을 한다. (세션정보등록하고 session 갯수 +1 됨)

이후 동일한 계정으로 사용자2가 로그인 시도

- 하지만 최대 허용 갯수는 1개라서 ConcurrentSessionControlAuthenticationStrategy에서 최대 허용갯수가 넘어서 **로그인 실패(인증 실패 전략의 경우 SessionAuthenticationException) 또는 session.expireNow() (이전 사용자 세션 만료 전략인 경우)**

이 상태에서 사용자 1이 서버에 접근 시

- ConcurrentSessionFilter가 매 요청마다 세션 만료 여부를 체크 → session.isExpire() true면 Logout처리 및 응답하게 된다.

사용자가 인증 할 때 SessionManagementFilter가 가지고 있는 각각의 필터를 활용해서 세션 고정 보호, 동시적 세션 제어, 세션등록을 하는 핵심적인 일을 인증 할 때 하게된다.

그 다음 ConcurrentSessionFilter가 요청마다 세션 만료여부를 판단하고 만료해야한다면 로그아웃하고 세션만료시키는 프로세스를 가지게 된다.

# 인가 API - 권한 설정 및 표현식

### 권한 설정

- 선언적 방식
  - URL 방식
    - http.antMatchers(”/users/**”).hasRole(”USER”)
- Mthod 방식

```  
  @PreAuthorize(”HasRole(’USER’)”)
  public void user() {…}
```


- 동적 방식 - DB 연동
  - URL 방식
  - Method 방식

![img_1.png](image/img_16.png)

![img_1.png](image/img_17.png)

anonymous()는 Role_anonymous 권한을 가진 사용자만 접근가능하다.

- role_user 권한을 가진 사용자도 anonymous에 접근 불가 (permitall() 필요)

hasRole과 hasAuthority의 차이점은 hasRole은 앞에 prefix인 role없이 user만 파라미터로 사용하고 hasAuthority는 role_user로 사용

기본적으로는 USER, ADMIN, SYS는 각각의 권한을 따로 가지고 있을 뿐이지 USER < ADMIN < SYS 와 같이 더 많은 권한을 가지고 있는 것이 아니다.

- 그래서 role에 따로 각각 적어줘야함.
- 혹은 이후에 학습할 role hierarchy 설정을 해주면 ADMIN은 USER 권한을 가지고 있는 것이 가능해짐.

실습 코드에서는 코드내에서 유저를 생성해놓고 사용하는 테스트 용도이지만 실제로는 동적으로 유저를 생성하고, 해당 유저의 권한과 정보들을 db에 저장해서 사용한다.

인가 정책도 antMatchers를 하나하나 적는게 아닌 자원에 해당하는 권한 설정들을 그때마다 필요한 권한설정을 실시간 적용이 되야하는데 선언적 방식은 동적으로 처리가 되지 않아서 좋지 않음.

이후 동적으로 인가 처리하는 방식 구현할 예정


# 인증/인가 API - ExceptionTranslationFilter, RequestCacheAwareFilter

![img_1.png](image/img_18.png)

ExceptionTranslationFilter는 크게 두가지 종류의 예외를 처리한다.

1. AuthenticationException
  - 인증 예외 처리
    - AuthenticationEntryPoint 호출
      - 로그인 페이지 이동, 401 오류 코드 전달 등
    - 인증 예외가 발생하기 전의 요청 정보를 저장
      - requestCache - 사용자의 이전 요청 정보를 저장하고 이를 꺼내오는 캐시 역할
        - SavedRequest - 사용자가 요청했던 request 파라미터 값들, 당시 헤더값들 등 저장.
        - 요청정보가 저장되는 값은 SavedRequest가 되고 해당 객체를 Session에 저장하는 것이 RequestCache가 된다.

2. AccessDeniedException
  - 인가 예외처리
    - AccessDeniedHandler에서 예외 처리하도록 제공


이 두가지 예외를 발생시키는 필터는 FilterSecurityInterceptor가 발생시킴.

- 스프링 시큐리티가 관리하는 보안 필터 중에서 가장 마지막에 위치한 필터이고 이 앞단에 위치한 필터가 ExceptionTranslationFilter이다.

ExceptionTranslationFilter가 사용자 요청을 받아서 다음 filter로 넘겨 줄 때 try~catch로 filterSecurityInterceptor를 호출한다.

- 그러면 filterSecurityInterceptor에서 발생한 예외는 ExceptionTranslationFilter가 각각 처리

![img_1.png](image/img_19.png)

- 그림에 부연설명을 하면 만약 인증을 받지않은 사용자가 접근을 하면 결국 익명(Anonymous) 사용자가 되어 인가 예외를 발생시켜서 AccessDeniedException이 되지만, 익명 사용자 or Remember-me 인증으로 인증된 사용자의 경우 AccessDeniedHandler가 아닌 인증예외인 AuthenticationException예외로 보냄.

- 인증 예외 발생하면 인증 실패 이후 처리 (SecurityContext null로 만듦) 후 로그인 페이지로 이동 및 사용자의 요청관련 정보 저장(”/user”)

- 만약 사용자가 인증을 받았지만 유저 권한을 가지고 있지만 어드민 권한이 필요한 자원에 접근하려고 할 때 인가 예외가 발생함.
  - 그러면 AccessDeniedException이 발생하고 AccessDeniedHandler에서 처리하도록 함.
  - 보통은 AccessDenined 페이지를 띄우도록 함.(사용자의 권한 필요하다는 메시지를 주는 페이지)

  ![img_1.png](image/img_20.png)


### RequestCacheAwareFilter

RequestCacheAwareFilter는 인증 예외시 원래 가고자 했던 요청 정보를 SavedRequest에 담게 되는데 이 객체가 존재하는지 확인하는 필터이다.

null이 아닌경우 다음 필터 호출 시 이전에 저장된 SavedRequest를 파라미터 값으로 사용함.

# Form 인증 - CSRF, CsrfFilter

![img_1.png](image/img_21.png)

**스프링은 CSRF을 방지하기 위한 Filter인 CsrfFIlter를 제공한다.**

![img_1.png](image/img_22.png)

타임리프와 같은 템플릿 엔진은 자동으로 csrf를 헤더에 넣어줌. 그러나 jsp같은 경우는 직접 만들어서 요청 보내야 함.

# 스프링 시큐리티 주요 아키텍처

## DelegatingFilterProxy

![img_1.png](image/img_23.png)

필터는 요청이 실제로 서블릿에서 받아서 처리하는데 서블릿에서 받기 전, 응답 후에 필터가 요청에 대한 일련의 작업을 수행 할 수 있다.

필터는 서블릿 스펙에 정의된 기술이기 때문에 서블릿 컨테이너에서 생성 및 실행된다.

그래서 필터는 스프링에서 관리하는 빈을 주입받거나 스프링에서 사용하는 기술을 필터에서 사용못한다.

- 실행되는 위치가 서블릿은 서블릿 컨테이너, 빈은 스프링 컨테이너임.

근데 스프링 시큐리티의 모든 인증, 인가처리는 필터기반으로 하고 있음.

- 하지만 빈 or 스프링에서 사용하는 기술을 필터에서는 사용 못함.
- 하지만 필터에서도 스프링에서 사용되는 기술을 사용하고자 함.
- 그래서 스프링 시큐리티에서는 필터기반으로 보안처리를 하는데 필터들은 스프링 기술들을 사용해야함.

그래서 스프링 빈에서 서블릿 필터를 구현한다.

- 그래도 사용자의 요청을 바로 받지는 못함. ( 서블릿 컨테이너에 위치한게 아니기 때문에)
- 그래서 was의 필터가 사용자의 요청을 받고 DelegatingFilterProxy(서블릿 필터)가 그 요청을 스프링에서 관리하는 필터빈(서블릿을 구현한 필터)에게 위임하는 역할을 한다.!

그럼 스프링 시큐리티는 필터 기반으로 보안 처리를 하면서 스프링의 기술들을 사용 할 수 있고, 서블릿 필터가 요청을 받아서 처리하기 때문에 DelegatingFilterProxy가 그 요청을 받게 되고, DelegatingFilterProxy가 실제로 보안처리를 하지는 않지만, 그 요청을 스프링에서 관리하는 필터빈에게 전달하고 스프링에서 필터 기반의 보안처리를 하게 되는 것이다.

- 요약 : DelegatingFilterProxy가 요청 받아서 서블릿 필터를 구현한 스프링 빈에게 요청처리 위임.
  - DelegatingFilterProxy는 특정한 이름을 가진 스프링 빈을 찾아 그 빈에게 요청을 위임한다.
  - springSecurityFilterChain이라는 이름을 가진 빈을 ApplicationContext에서 찾아 요청을 위임.


## FilterChainProxy

![img_1.png](image/img_24.png)

- DelegatingFilterProxy는 springSecurityFilterChain을 이름으로 가진 빈을 찾아서 위임하는데 그것이 FilterChainProxy이다.
- 결국 FilterChainProxy에서 DelegatingFilterProxy으로부터 요청을 위임 받고 실제 보안처리를 함.
- FilterChainProxy는 스프링 시큐리티 초기화 시 생성되는 필터들을 관리하고 제어
  - 스프링 시큐리티가 기본적으로 생성하는 필터
  - 설정 클래스에서 API 추가 시 생성되는 필터
- 사용자의 요청을 필터 순서대로 호출하여 전달
- 사용자정의 필터를 생성해서 기존의 전.후로 추가 가능
  - 필터의 순서를 잘 정의
- 마지막 필터까지 인증 및 인가 예외가 발생하지 않으면 보안 통과함.

![img_1.png](image/img_25.png)

사용자의 요청부터 DelegatingFilterProxy → FilterChainProxy의 전체적인 흐름.

- DelegatingFilterProxy가 springSecurityFilterChain이라는 이름의 빈을 찾아서 위임한다고 했는데 DelegatingFilterProxy도 필터로 등록 될 때 springSecurityFilterChain라는 이름으로 등록이 된다. 그래서 같은 이름의 빈에게 요청을 위임하는것임. (내부적으로)
- 그래서 그 이름(springSecurityFilterChain)을 가진 빈이 FilterChainProxy인 것이다.
- 요청을 위임 받은 FilterChainProxy는 가지고 있는 필터들을 수행하면서 각각의 보안처리를 하게 되고, 모두 성공적으로 수행하고 나면 최조
- 요청을 위임 받은 FilterChainProxy는 가지고 있는 필터들을 수행하면서 각각의 보안처리를 하게 되고, 모두 성공적으로 수행하고 나면 최종자원(?)인 SpringMVC의 DispatcherServlet에게 요청을 전달한다.

- DelegatingFilterProxy는 SecurityFilterAutuConfiguration에 의해서 생성되고, FilterChainProxy는 WebSecurityConfiguration에 의해 생성됨.
  - 둘 다 DEFAULT_FILTER_NAME (springSecurityFilterChain)으로 생성.
- # 필터 초기화와 다중 보안 설정

![img_1.png](image/img_26.png)

**만약 보안과 관련된 설정 클래스가 2가지 이상 있을 때 어떠한 방식과 방법으로 사용할 수 있는가?**

- 설정 클래스(SecurityConfig1, SecurityConfig2)가 있을 때 각각 따로따로 보안 기능이 작동한다.
- 그리고 설정 클래스별로 RequestMatcher를 설정할 수 있다.
  - 그러면 해당 경로에 따라서 설정클래스에 해당하는 보안기능이 작도오딘다.
- 만약 SecurityConfig1과 2를 만들어서 구성을 했으면 초기화 시 어떻게 각각 다르게 만드는가?
  - SecurityFilterChain이라는 객체안에 Filters안에 SecurityConfig에서 필터를 생성한 것을 담게 된다.
  - 또, SecurityConfig에서 requestMatcher 정보가 담긴 SecurityFilterChain이라는 객체가 생성이 된다.
  - 또, 각각의 SecurityFilterChain 객체를 FilterChainProxy라는 객체의 변수(SecurityFilterChains)에서 가지고 있게 된다.
  - 그러면 결국 FilterChainProxy.에서 SecurityFilterChain이라는 객체들을 가지고 있게 되고, 만약 사용자가 /admin과 같은 url로 요청을 하면 delegatingFilterProxy에서 FilterChainProxy로 요청을 위임하고, 받아서 요청을 처리 할 때 어떤 SecurityFilterChain을 사용할 것인지 판단하게 되는데 그 안에 RequestMatcher에 매칭이 되는 필터를 사용해서 인증 or 인가처리를 하게 된다.

  **요약.**

  ![img_1.png](image/img_27.png)

- 만약 SecurityConfig 와 같은 설정파일들이 여러개라면 @Order라는 어노테이션으로 순서를 지정해줘야한다.
  - 요청url로 그럼 필터를 선택할 때 해당 order 순서에 맞는 SecurityFilterChain을 먼저 찾게 된다.
    - 그래서 좀 더 자세한(?) url matcher를 가진 SecurityConfig를 Order를 더 낮게주고(우선순위를 더 높게) 좀 더 넓은 범위의 SecurityConfig를 Order를 더 높게(우선순위를 더 낮게) 줘야 한다.
    - 그렇지 않으면 더 넓은 범위의 보안 설정클래스에 먼저 걸리기 때문에 자세한 범위의 보안 설정클래스가 실행되지 않는다.

# 인증 개념 이해 - Authentication

![img_1.png](image/img_28.png)

authentication은 인증 주체를 의미

- 스프링 시큐리티에서는 Authentication객체를 사용자의 인증정보를 저장하는 토큰 개념으로 사용.
- 인증 시 id와 password를 담고 인증 검증을 위해 전달되어 사용된다.
- 인증 후 최종 인증 결과(user 객체, 권한정보)를 담고 security Context에 저장되어 전역적으로 참조.
  - Authentication authentication = securityContextHolder.getContext().getAuthentication()

- 구조
  - principal : 사용자 아이디 or User 객체 저장
  - credentials : 사용자 비밀번호
  - authorities : 인증된 사용자의 권한 목록
  - details : 인증 부가 정보
  - Authenticated : 인증 여부

Authentication이 인증 시, 인증이 끝난 후 각각 어떻게 활용이 되는지

![img_1.png](image/img_29.png)

- 사용자는 username과 password를 요청 시 전달.
- usernamePasswordAuthenticationFilter는 요청에 담겨있는 username과 password를 추출
- Authentication 객체를 만듬
  - 속성중 principal에는 username을, Credentials에는 password 정보를 넣는다.
- AuthenticationManager가 이전에 만든 Authentication을 가지고 인증을 한다.
  - 인증 실패를 하면 당연히 예외 발생.
- 인증 성공 시 AuthenticationManager가 새로운 Authentication을 만든다.
  - 속성 중 Principal을 UserDetails를 담고, Credentials에는 Password를 담고(보안상 비워두기도 함) Authorities는 권한 목록을 담아서 만들다.
- 인증 성공 후 생성한 Authentication 객체를 ThreadLocal - SecurityContextHolder - SecurityContext 안에 Authentication 객체로 저장한다.

# SecurityContextHolder, SecurityContext

![img_1.png](image/img_30.png)

SecurityContext는 인증 객체를 저장하는 보관소.

- ThreadLocal에 저장되어 아무곳에서나 참조가 가능.
  - Thread 마다 고유하게 할당된 저장소가 ThreadLocal이다.
- 인증이 완료되면 HttpSession에 저장되어 어플리케이션 전반에 걸쳐 전역적인 참조가 가능.

SecurityContextHolder

- SecurityContext 객체 저장 방식
  - MODE에 따라서 어느 범위까지 SecurityContext를 저장해서 사용할 것인지 설정 가능.
  - default는 MODE_THREADLOCAL로 스레드 당 SecurityContext객체를 할당.
- SecurityContextHolder.clearContext() : SecurityContext 기본 정보 초기화

![img_1.png](image/img_31.png)

# SecurityContextPersistenceFilter

![img_1.png](image/img_32.png)

SecurityContextPersistenceFilter는 SecurityContext 객체의 생성, 저장, 조회를 하는 일을 함.

- 익명사용자, 인증 시, 인증 후, 최종 응답 후 공통적으로 하는일이 각각 있음.

- 익명 사용자의 경우 새로운 securityContext 객체를 생성해서 SecurityContextHolder에 저장.

인증 시

- 익명사용자처럼 새로운 securityContext 객체를 생성해서 SecurityContextHolder에 저장.
- 그리고 form 인증 시  UsernamePasswordAuthenticationFilter에서 인증하고 성공하면 SecurityContext에 UsernamePasswordAuthentication객체를 SecurityContext에 저장
- 인증이 최종 완료되면 SecurityContextPersistenceFilter는 Session에 SecurityContext를 저장.

인증 후

- Session에서 SecurityContext 를 꺼내서 SecurityContextHolder에 저장하고 인증 시 SecurityContext안에 있는 Authentication 객체가 존재하기 때문에 계속 인증을 유지할 수 있다.

최종 응답 시에는 공통적으로 SecurityContextHolder에서 SecurityContext를 clear하는데 이는 매 요청마다 SecurityContext를 SecurityContextHolder에 만들거나 기존에 존재하는 것을 저장하게 되기 때문임.

![img_1.png](image/img_33.png)

- SecurityContextPersistenceFilter는 내부적으로 HttpSecurityContextRepository를 가지고 있음.
  - HttpSecurityContextRepository는 실제 SecurityContext를 생성하거나 Session에서 조회해서 SecurityContextHolder에 넣어주는 일을 함.
- 인증 전이라면 SecurityContext를 생성 후 chain.dofilter를 통해 인증을 하는 filter에게 체이닝함.
- form인증의 경우 usernamePasswordFilter에서 인증을 하고 AuthenticationToken을 SecurityContext에 저장하게 됨.
- 이후 필터 체이닝을 거치다가 최종적으로 클라이언트한테 응답할때 SecurityContextPersistenceFilter가 Session에 SecurityContext를 저장.
- 그 후 최종 응답 시 SecurityContextHolder.clearContext()를 통해 SecurityContext를 삭제함.

요약 : SecurityContextPersistenceFilter는 인증시에는 SecurityContext를 생성하고 SecurityContextHolder에 넣어주기만 하고 다음 인증 필터로 넘긴다. 그리고 응답 전에 Session에 SecurityContext를 저장한다.

인증시에는 세션에서 SecurityContext를 꺼내서 SecurityContextHolder에 넣고 다음 필터로 체이닝.

### 구조

![img_1.png](image/img_34.png)

# Authentication Flow(인증의 흐름)

![img_1.png](image/img_35.png)

1. 사용자가 form 로그인으로 인증 요청을 보내면 UsernamePasswordAuthenticationFilter에서 받은 후 입력받은 id,password를 가지고 AuthenticationToken을 생성해서 AuthenticationManager를 호출한다.
2. AuthenticationManager는 인증처리하는 객체는 아니고 인증의 전반적인 관리를 하는데 인증을 처리하는 AuthenticationProvider 목록들을 가지고 있는데 적절한 AuthenticationProvider에게 인증을 하도록 위임한다.
3. 인증을 위해 AuthenticationProvider가 호출되면 Authentication(사용자가 입력한 Id,Pwd)에서 username을 통해 userDetails 객체를 얻기위해 UserDetailsService의 loadByUsername을 호출한다.
4. UserDetailsService에서는 파라미터로 받은 UserName을 통해 유저 객체를 조회한 후 UserDetails타입으로 반환한다.
  1. 만약 유저를 찾지 못하면 예외가 발생.
5. 다시 AuthenticationProvider는 UserDetails객체를 받아서 사용자가 입력한 password와 username으로 조회한 UserDetails에 있는 Password와 같은지 확인한다.
  1. 만약 다를 경우 BadCredentialException 발생.
6. 인증에  성공하면 Authentication 객체를 만들어서 UserDetails와 authorities(해당 유저가 가진 권한 목록)담아 리턴
7. AuthenticationManager도 그대로 받아서 리턴
8. UsernamePasswordAuthenticationFilter에서 SecurityContext안에 Authentication 객체를 넣게 됨.


# AuthenticationManager

![img_1.png](image/img_36.png)

AuthenticationManager는 인증처리를 할 AuthenticationProvider를 찾는 역할을 한다.

사용자의 인증 요청(폼인증, 리멤버 미 인증, Oauth 인증 등)이 들어오면 ProviderManager가 받아서 각 인증에 맞는 실제 인증처리를 할 AuthenticationProvider를 찾는다.

만약 해당 ProviderManager가 처리할 AuthenticationProvider 가 없다면 parent(AuthenticationManager타입의 ProviderManager)속성에 가지고 있는 ProviderManager를 탐색하여 인증처리를 할 AuthenticationProvider를 찾는다.

먼저 생성한것이 parent 속성으로 들어가게 됨….

# AuthenticationProvider

![img_1.png](image/img_37.png)

AuthenticationProvider는 인증처리를 하는 실질적인 객체이다.

AuthenticationManager에게 authenticate 메서드가 호출이 되면 사용자의 id로 조회를 해서 userDetails객체에 맞는 사용자를 가져온다. (없으면 userNotFoundException)

그리고 사용자가 입력한 비밀번호와 userDetails에 담겨있는 비밀번호를 비교하고 만약 일치하지 않으면 BadCredentialException 발생

이후 추가 검증할 것이 있다면 추가 검증을 하고 Authentication객체에 user(UserDetails)와 authorities(권한목록)을 담아 다시 AuthenticationManager에게 반환한다.

supports(authentication)은 해당 AuthenticationProvider에서 실제 인증 처리를 할 수 있는지 검증하는 메서드


# Authorization & FilterSecurityInterceptor

![img_1.png](image/img_38.png)

Authorization은 인가처리에 대한 내용임.

- 인증을 받은 유저가 무엇이 허가 되었는지 증명하는 것
- Spring 시큐리티는 Authentication과 Authorization으로 인증과 인가 두가지로 나누어져 있음.

### FilterSecurityInterceptor

![img_1.png](image/img_39.png)

FilterSecurityInterceptor는 맨 마지막에 있는 필터로 인증된 사용자에 대해서 요청의 승인/거부 여부를 최종 결정.

인증안하고 접근 시도시 AuthenticationException, 인증 후 자원 접근 시도 시 권한 없을 경우 AccessDeniedException 발생.

권한 처리는 AccessDecisionManager에게 맡기는데 실제로는 AccessDecisionVoter에 의해서 권한 처리 판단을 하게 됨.

![img_1.png](image/img_40.png)

- FilterSecurityInterceptor가 사용자 요청을 받아서 인증 여부 체크 → 인증 객체 null 이면 AuthenticationException 발생하고 ExceptionTranslationFilter가 처리함 (ex. 로그인페이지로 이동)
- 인증객체 존재하면 SecurityMetadataSource를 통해서 사용자가 요청한 자원에 접근할 때 필요한 권한 정보 조회해서 전달 후 필요한 권한정보가 없으면 심사하지 않고 자원 접근 허용을 한다.
- 필요한 권한정보가 있다면 AccessDecisionmanager가 AccessDecisionVoter에게 권한이 있는지 심의 요청을 하고 AccessDecisionVoter가 심의 후 승인/거부 판단을 한다.
- 접근 승인에 실패하면 AccessdeniedException 발생하고 성공 시 자원 접근에 허용하게 된다.

# AccessDecisionManager, AccessDecisionVoter

![img_1.png](image/img_41.png)

- AccessDesicionManager는 사용자의 자원 접근을 허용할지, 거부할지 최종 결정한다.
- 여러 개의 voter를 가지고 각 voter로부터 접근허용, 거부, 보류에 해당하는 값을 리턴 받고 판단해서 결정한다.
- 최종 접근 거부 시 예외발생 (AccessDeniedException)

AccessDesicionManger 인터페이스로 구현체에 따라 접근 결정하는 유형이 나누어진다.

- AffirmativeBased:
  - 여러 Voter중 하나라도 접근 허가 시 최종 접근 허가
- ConsensusBased:
  - 다수표에 의해 최종 결정을 한다.
  - 동수일 경우, 기본 접근은 허가이나, allowIfEqualGrantedDeniedDecisions을 false로 설정할 경우 접근 거부로 변경됨,.
- UnanimousBased:
  - 모든 voter가 만장일치로 접근을 승인해야 최종승인 하며 그렇지 않은 경우 접근을 경우(하나라도 거부 시 최종거부)

  ![img_1.png](image/img_42.png)

  - voter가 인증정보, 요청정보, 권한정보를 받아서 접근을 허용할지, 거부할지, 보류할지 판단하게 된다.
  - 결정 방식으로
    - ACCESS_GRANTED : 접근 허용(1)
    - ACCESS_DENIED : 접근 거부 (-1) (사진이 잘못됨 -1이 맞음)
    - ACCESS_ ABSTAIN : 접근 보류(0)
      - Voter가 해당 타입의 요청에 대해 결정을 내릴 수 없는 경우

  ### 흐름

  ![img_1.png](image/img_43.png)

  FilterSecurityInterceptor가 인가처리를 AccessDesicionManager에게 맡김.

  - 이때 인증정보, 요청정보, 권한정보에 대한 것을 넘겨줌

  다시 AccessDecisionManager에서 Voter들에게 판단을 맡김

  - 이때 인증정보, 요청정보, 권한정보에 대한 것을 넘겨줌
  - 각 voter는 Access_Granted, Access_Denied, Access_Abstain 중 하나를 반환

  AccessDecisionManager는 구현체에 맞게 허용/거부를 판단하고

  - 허용 시 Access_Granted를 FilterSecurityInterceptor에 리턴
  - 거부 시 Access_Denied를 ExceptionTranslationFilter 호출

# 스프링 시큐리티 아키텍처 정리

![img_1.png](image/img_44.png)


---

# 실습

# PasswordEncoder
![img_1.png](image/img_45.png)

# Form 인증 - WebAuthenticationDetails, AuthenticationDetailsSource

![img_1.png](image/img_46.png)

- 유저가 인증 시도를 하면 해당 필터가 Authentication 객체를 만들고 setDetails라는 메서드를 통해서 id,pwd 말고도 다른 전달된 데이터를 Authentication의 details라는 객체안에 가지고 있게 된다.
- details는 object 타입이고 실제로는 WebAuthenticationDetails로 데이터를 가지고 있는데 기본적으로는 sessionId와 remoteAddress를 가지고 있고 커스텀해서 더 많은 데이터를 저장할 수 있다.
- WebAuthenticationDetails 객체를 만드는 것이 AuthenticationDetailsSource가 된다.


# Ajax 인증 프로세스 요약

![img_1.png](image/img_47.png)

# Ajax 인증 -AjaxAuthenticationFilter  

![img_1.png](image/img_48.png)
- AbstractAuthenticationProcessingFilter는 추상클래스로 상속 받아서 사용
- usernamepasswordFilter도 해당 필터 상속받음
 
