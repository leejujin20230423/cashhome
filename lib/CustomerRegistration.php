<?php
declare(strict_types=1);

/** Shared by public intake and the authenticated repair of pre-existing inquiries. */
function cashhome_customer_text(array $input,string $key,int $max):string {
    if(!is_string($input[$key]??''))throw new InvalidArgumentException('고객정보의 입력 형식을 확인해 주세요.');
    $value=trim($input[$key]??'');
    if(mb_strlen($value)>$max)throw new InvalidArgumentException('고객정보의 입력 길이를 확인해 주세요.');
    return $value;
}
function cashhome_customer_date(string $value):bool {
    $date=DateTimeImmutable::createFromFormat('!Y-m-d',$value,new DateTimeZone('Asia/Seoul'));
    $today=(new DateTimeImmutable('today',new DateTimeZone('Asia/Seoul')))->format('Y-m-d');
    return $date&&$date->format('Y-m-d')===$value&&$value>='1900-01-01'&&$value<=$today;
}
function cashhome_customer_birth(array $customer):string {
    $birth=(string)($customer['E_cash_customer_birth_date']??'');
    if(cashhome_customer_date($birth))return $birth;
    $resident=preg_replace('/\D/','',(string)($customer['E_cash_customer_lincense_id']??''));
    if(strlen($resident)!==13)return '';
    $century=['1'=>'19','2'=>'19','3'=>'20','4'=>'20','5'=>'19','6'=>'19','7'=>'20','8'=>'20'][$resident[6]]??'';
    $birth=$century.substr($resident,0,2).'-'.substr($resident,2,2).'-'.substr($resident,4,2);
    return cashhome_customer_date($birth)?$birth:'';
}
function cashhome_customer_input(array $input):array {
    $clean=[];$errors=[];
    foreach(['name'=>80,'phone'=>30,'birth_date'=>10,'job'=>50,'addr_live'=>255,'addr_live_detail'=>255,'addr_resident'=>255,'addr_resident_detail'=>255] as $key=>$max){
        try{$clean[$key]=cashhome_customer_text($input,$key,$max);}catch(InvalidArgumentException $e){$errors[]=$e->getMessage();$clean[$key]='';}
    }
    $clean['phone']=preg_replace('/\D/','',$clean['phone']);
    if(mb_strlen($clean['name'])<2)$errors[]='성함을 2자 이상 입력해 주세요.';
    if(!preg_match('/^0\d{8,10}$/D',$clean['phone']))$errors[]='연락처를 정확히 입력해 주세요.';
    if(!cashhome_customer_date($clean['birth_date']))$errors[]='생년월일을 정확히 입력해 주세요.';
    if($clean['job']==='')$errors[]='직업을 입력해 주세요. 해당 사항이 없으면 무직으로 입력합니다.';
    foreach(['addr_live'=>'실거주지 주소','addr_live_detail'=>'실거주지 상세주소','addr_resident'=>'등본 주소지','addr_resident_detail'=>'등본 상세주소'] as $key=>$caption)if($clean[$key]==='')$errors[]=$caption.'를 입력해 주세요.';
    return [$errors,$clean];
}
function cashhome_customer_begin(PDO $pdo,array $clean):?string {
    $lock=null;
    if($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'){
        $database=(string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        $lock='cashhome-client-'.substr(hash('sha256',$database.'|'.$clean['phone'].'|'.$clean['birth_date']),0,48);
        $s=$pdo->prepare('SELECT GET_LOCK(?,5)');$s->execute([$lock]);
        if((int)$s->fetchColumn()!==1)throw new RuntimeException('Customer intake is busy');
    }
    try{$pdo->beginTransaction();}catch(Throwable $e){cashhome_customer_unlock($pdo,$lock);throw $e;}
    return $lock;
}
function cashhome_customer_unlock(PDO $pdo,?string $lock):void {
    if($lock===null)return;
    try{$s=$pdo->prepare('SELECT RELEASE_LOCK(?)');$s->execute([$lock]);}catch(Throwable $e){error_log('[customer intake] lock release failed');}
}
function cashhome_customer_register(PDO $pdo,array $input,string $registeredAt):int {
    if(!$pdo->inTransaction())throw new LogicException('Customer registration requires the inquiry transaction');
    [$errors,$clean]=cashhome_customer_input($input);
    if($errors)throw new InvalidArgumentException(implode(' ',$errors));
    $s=$pdo->prepare('SELECT * FROM E_cash_customer WHERE TRIM(E_cash_customer_name)=?');$s->execute([$clean['name']]);
    $matches=[];$unknown=false;
    // A previously verified resident number is used only for repairing an authenticated old inquiry.
    $resident=preg_replace('/\D/','',(string)($input['verified_resident_number']??''));
    foreach($s->fetchAll(PDO::FETCH_ASSOC) as $customer){
        $phone=preg_replace('/\D/','',(string)($customer['E_cash_customer_contact']??''));
        $birth=cashhome_customer_birth($customer);
        $sameResident=strlen($resident)===13&&$resident===preg_replace('/\D/','',(string)($customer['E_cash_customer_lincense_id']??''));
        if($birth===$clean['birth_date']&&($sameResident||$phone===$clean['phone']))$matches[]=$customer;
        elseif($phone===$clean['phone']&&$birth==='')$unknown=true;
    }
    if(count($matches)>1||$unknown)throw new InvalidArgumentException('고객정보를 하나로 확인할 수 없어 접수하지 못했습니다. 입력 내용을 확인하거나 담당자에게 문의해 주세요.');
    if(count($matches)===1)return (int)$matches[0]['E_cash_customer_id'];
    $values=['E_cash_customer_registration_date'=>substr($registeredAt,0,10),'E_cash_customer_name'=>$clean['name'],'E_cash_customer_birth_date'=>$clean['birth_date'],'E_cash_customer_job'=>$clean['job'],'E_cash_customer_contact'=>$clean['phone'],'E_cash_customer_address'=>$clean['addr_live'].' '.$clean['addr_live_detail']];
    // Existing profiles are never overwritten by information submitted on a public form.
    $keys=array_keys($values);$s=$pdo->prepare('INSERT INTO E_cash_customer ('.implode(',',$keys).') VALUES ('.implode(',',array_fill(0,count($keys),'?')).')');$s->execute(array_values($values));
    return (int)$pdo->lastInsertId();
}
function cashhome_customer_attach(PDO $pdo,int $inquiryId,int $customerId,array $clean):void {
    if(!$pdo->inTransaction())throw new LogicException('Customer linking requires the inquiry transaction');
    $s=$pdo->prepare('UPDATE cashhome_1000_inquiries SET cashhome_1000_customer_id=?,cashhome_1000_customer_birth_date=?,cashhome_1000_customer_job=? WHERE cashhome_1000_id=?');
    $s->execute([$customerId,$clean['birth_date'],$clean['job'],$inquiryId]);
    if($s->rowCount()===0){$s=$pdo->prepare('SELECT cashhome_1000_customer_id FROM cashhome_1000_inquiries WHERE cashhome_1000_id=?');$s->execute([$inquiryId]);if((int)$s->fetchColumn()!==$customerId)throw new RuntimeException('Inquiry link was not persisted');}
}
