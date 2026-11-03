<?php
if(PHP_SAPI!=='cli')exit;
require_once __DIR__.'/../lib/CustomerRegistration.php';
function customer_check(bool $ok,string $why):void {if(!$ok)throw new RuntimeException($why);}
function customer_count(PDO $p,string $table):int {return (int)$p->query('SELECT COUNT(*) FROM '.$table)->fetchColumn();}
function customer_insert(PDO $p,string $table,array $data):int {$keys=array_keys($data);$s=$p->prepare('INSERT INTO '.$table.' ('.implode(',',$keys).') VALUES ('.implode(',',array_fill(0,count($keys),'?')).')');$s->execute(array_values($data));return (int)$p->lastInsertId();}
function customer_registration_test(PDO $p):void {
    $d=['name'=>'합성 고객','phone'=>'010-0000-1234','birth_date'=>'1990-01-02','job'=>'회사원','addr_live'=>'합성 실거주지','addr_live_detail'=>'101호','addr_resident'=>'합성 등본 주소','addr_resident_detail'=>'102호'];
    [$errors,$clean]=cashhome_customer_input($d);customer_check(!$errors&&$clean['phone']==='01000001234','complete customer input normalized');
    foreach(array_keys($d) as $key){[$errors]=cashhome_customer_input(array_replace($d,[$key=>'']));customer_check((bool)$errors,'missing required '.$key);}
    foreach([['birth_date'=>'1900-02-29'],['birth_date'=>'2100-01-01'],['job'=>str_repeat('x',51)],['name'=>[]],['phone'=>'123']] as $bad){[$errors]=cashhome_customer_input(array_replace($d,$bad));customer_check((bool)$errors,'malformed customer input rejected');}
    customer_check(cashhome_customer_date('2000-02-29')&&!cashhome_customer_date('2026-02-29'),'leap date validation');
    customer_check(!array_key_exists('verified_resident_number',cashhome_customer_input($d+['verified_resident_number'=>'not trusted'])[1]),'public input cannot supply verified identity');
    $persist=function(array $input,bool $fail=false)use($p):array {
        [$errors,$input]=cashhome_customer_input($input);if($errors)throw new InvalidArgumentException(implode(' ',$errors));
        $lock=cashhome_customer_begin($p,$input);
        try{
            $id=cashhome_customer_register($p,$input,'2026-11-04 12:00:00');
            $inquiry=customer_insert($p,'cashhome_1000_inquiries',['cashhome_1000_created_at'=>'2026-11-04 12:00:00','cashhome_1000_customer_name'=>$input['name'],'cashhome_1000_customer_phone'=>$input['phone'],'cashhome_1000_privacy_policy_version'=>'customer-v2-20261104','cashhome_1000_applicant_type'=>'delivery']);
            cashhome_customer_attach($p,$inquiry,$id,$input);
            customer_insert($p,'cashhome_1100_consent_logs',['cashhome_1100_inquiry_id'=>$inquiry,'cashhome_1100_consent_type'=>'privacy','cashhome_1100_consent_version'=>'customer-v2-20261104','cashhome_1100_consented'=>1]);
            if($fail)throw new RuntimeException('synthetic consent failure');
            $p->commit();return [$id,$inquiry];
        }catch(Throwable $e){if($p->inTransaction())$p->rollBack();throw $e;}finally{cashhome_customer_unlock($p,$lock);}
    };
    [$id,$inquiry]=$persist($d);$row=$p->query('SELECT * FROM E_cash_customer WHERE E_cash_customer_id='.$id)->fetch(PDO::FETCH_ASSOC);
    customer_check($row['E_cash_customer_birth_date']===$d['birth_date']&&$row['E_cash_customer_job']==='회사원','new customer profile saved');
    customer_check((int)$p->query('SELECT cashhome_1000_customer_id FROM cashhome_1000_inquiries WHERE cashhome_1000_id='.$inquiry)->fetchColumn()===$id,'new inquiry stores customer PK');
    customer_check(empty($row['E_cash_customer_lincense_id']),'no new resident number collected');
    $count=customer_count($p,'E_cash_customer');[$again]=$persist(array_replace($d,['job'=>'변경 신청 직업','addr_live_detail'=>'다른 신청 주소']));
    customer_check($again===$id&&customer_count($p,'E_cash_customer')===$count&&$p->query('SELECT * FROM E_cash_customer WHERE E_cash_customer_id='.$id)->fetch(PDO::FETCH_ASSOC)===$row,'repeat inquiry reuses PK without overwriting original profile');
    [$different]=$persist(array_replace($d,['birth_date'=>'1991-01-02']));customer_check($different!==$id,'different birth dates do not merge people');
    $legacy=customer_insert($p,'E_cash_customer',['E_cash_customer_name'=>'합성 기존 고객','E_cash_customer_contact'=>'01000001235','E_cash_customer_lincense_id'=>'9001021000000']);
    [$old]=$persist(array_replace($d,['name'=>'합성 기존 고객','phone'=>'01000001235']));customer_check($old===$legacy,'existing verified birth date derives from stored legacy identity');
    $before=[customer_count($p,'E_cash_customer'),customer_count($p,'cashhome_1000_inquiries'),customer_count($p,'cashhome_1100_consent_logs')];
    try{$persist(array_replace($d,['name'=>'합성 실패 고객','phone'=>'01000001236']),true);throw new LogicException('rollback not exercised');}catch(RuntimeException $e){customer_check($e->getMessage()==='synthetic consent failure','expected failure');}
    customer_check($before===[customer_count($p,'E_cash_customer'),customer_count($p,'cashhome_1000_inquiries'),customer_count($p,'cashhome_1100_consent_logs')],'customer, inquiry, and consent roll back together');
    customer_insert($p,'E_cash_customer',['E_cash_customer_name'=>$clean['name'],'E_cash_customer_contact'=>$clean['phone'],'E_cash_customer_birth_date'=>$clean['birth_date']]);
    try{$persist($d);throw new LogicException('ambiguous match accepted');}catch(InvalidArgumentException $e){}
    customer_check(customer_count($p,'cashhome_1000_inquiries')===$before[1],'ambiguous identities leave no orphan inquiry');
    customer_insert($p,'E_cash_customer',['E_cash_customer_name'=>'합성 확인 필요','E_cash_customer_contact'=>'01000001237']);
    try{$persist(array_replace($d,['name'=>'합성 확인 필요','phone'=>'01000001237']));throw new LogicException('unknown birth accepted');}catch(InvalidArgumentException $e){}
    customer_insert($p,'E_cash_customer',['E_cash_customer_name'=>'합성 확인 필요','E_cash_customer_contact'=>'01000001237','E_cash_customer_birth_date'=>$clean['birth_date']]);
    try{$persist(array_replace($d,['name'=>'합성 확인 필요','phone'=>'01000001237']));throw new LogicException('known profile selected despite an ambiguous unknown profile');}catch(InvalidArgumentException $e){}
    customer_check(!$p->inTransaction(),'all error paths release transactions');
    echo 'PASS: required fields, valid dates, normalized contact, customer PK, repeat reuse, original-profile preservation, legacy matching, ambiguous/unknown identity rejection and atomic rollback.',PHP_EOL;
}
if(!defined('CUSTOMER_TEST_PRELOADED')){
    $p=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
    $p->exec('CREATE TABLE E_cash_customer(E_cash_customer_id INTEGER PRIMARY KEY AUTOINCREMENT,E_cash_customer_registration_date TEXT,E_cash_customer_name TEXT,E_cash_customer_birth_date TEXT,E_cash_customer_job TEXT,E_cash_customer_lincense_id TEXT,E_cash_customer_contact TEXT,E_cash_customer_address TEXT)');
    $p->exec('CREATE TABLE cashhome_1000_inquiries(cashhome_1000_id INTEGER PRIMARY KEY AUTOINCREMENT,cashhome_1000_created_at TEXT,cashhome_1000_customer_name TEXT,cashhome_1000_customer_phone TEXT,cashhome_1000_privacy_policy_version TEXT,cashhome_1000_applicant_type TEXT,cashhome_1000_customer_id INTEGER,cashhome_1000_customer_birth_date TEXT,cashhome_1000_customer_job TEXT)');
    $p->exec('CREATE TABLE cashhome_1100_consent_logs(cashhome_1100_id INTEGER PRIMARY KEY AUTOINCREMENT,cashhome_1100_inquiry_id INTEGER,cashhome_1100_consent_type TEXT,cashhome_1100_consent_version TEXT,cashhome_1100_consented INTEGER)');
    customer_registration_test($p);
}
