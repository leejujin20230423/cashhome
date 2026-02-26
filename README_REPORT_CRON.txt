CashHome 관리자 리포트 메일(3시간마다)

- 수신자: ecashhome@gmail.com
- 최근 3개월 기준 요약/상세 목록을 admin_inquiries.php의 report 명령으로 발송합니다.

[크론 예시]
0 */3 * * * /usr/bin/php /var/www/html/cashhome/admin_inquiries.php report >> /var/log/cashhome_report.log 2>&1

※ 서버 경로(/var/www/html/...)는 실제 설치 경로로 바꿔주세요.
※ Gmail SMTP 사용을 위해 환경변수 GMAIL_APP_PASSWORD 설정이 필요합니다.
   예) export GMAIL_USER=ecashhome@gmail.com
       export GMAIL_APP_PASSWORD=앱비밀번호
