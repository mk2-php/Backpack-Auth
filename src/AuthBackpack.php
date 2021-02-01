<?php

namespace mk2\backpack_auth;

use Mk2\Libraries\Backpack;
use mk2\backpack_encrypt\EncryptBackpack;

class AuthBackpack extends Backpack{

    private $allPageAllow=false;
    private $allowPages=null;

    public $name="userAuthority";

    public $table="User";

    public $colum=[
        "username"=>"username",
        "password"=>"password",
    ];

	public $hash=[
        "algolizum"=>"sha256",
		"Salt"=>"mk2authhashsalt********************************",
        "stretch"=>6,
    ];

    public $where=null;
    
    public $redirectLogin=null;

    public $altanativeEncrypt="Encrypt";
    public $altanativeSession="Session";

    public $tokenName="__token";
    public $loginedDateName="__logined";

	/**
	 * __construct
	 */
	public function __construct(){
		parent::__construct();
		
        $this->Backpack->load([
            $this->altanativeEncrypt,
            $this->altanativeSession,
        ]);
       $this->Table->load($this->table);

    }

    /**
     * verify
     */
    public function verify(){

        if($this->allPageAllow){
            return true;
        }

        if(is_array($this->allowPages)){
            foreach($this->allowPages as $page){
                if($this->Request->params("action")==$page){
                    return true;
                }
            }
        }
        $redirectUrl=$this->Response->url($this->redirectLoginPage);

        if($redirectUrl==$this->Request->params("path")){
            return true;
        }

        // token check
        $token=$this->getAuth($this->tokenName);

        $jugement=true;
        if(!$token){
            $jugement=false;
        }

        if($token!=$this->_makeToken($this->getAuth($this->loginedDateName))){
            $jugement=false;
        }

        if(!$jugement){
            $this->Response->redirect($redirectUrl);
        }

        return true;

    }

    /**
     * login
     * @param $post 
     */
    public function login($post){
        
        $username=$post[$this->colum["username"]];
        $password=$post[$this->colum["password"]];

        $password=$this->getPasswordHash($password);

        $obj=$this->Table->{$this->table}->select()
            ->where($this->colum["username"],"=",$username)
            ->where($this->colum["password"],"=",$password)
        ;

        if(is_array($this->where)){
            foreach($this->where as $w_){
                $obj->where(...$w_);
            }
        }

        $res=$obj->first()->row();

        if(!$res){
            return false;
        }

        unset($res->{$this->colum["password"]});

        $logined=date_format(date_create("now"),"Y-m-d H:i:s");

        $res->{$this->loginedDateName}=$logined;
        $res->{$this->tokenName}=$this->_makeToken($logined);

        $this->Backpack->{$this->altanativeSession}->changeSSID();
        $this->Backpack->{$this->altanativeSession}->write($this->name,$res);

        return true;
    }

    /**
     * logout
     */
    public function logout(){
        $this->Backpack->{$this->altanativeSession}->delete($this->name);
        $this->Backpack->{$this->altanativeSession}->changeSSID();
    }

    /**
     * alloow
     * @params $pages = null
     */
    public function allow($pages=null){

        $this->allPageAllow=false;

        if($pages){
            $this->allowPages=$pages;
        }
        else{
            $this->allPageAllow=true;
        }
        return $this;
    }

    /**
     * getAuth
     * @params $name
     */
    public function getAuth($name=null){

        $buffer=$this->Backpack->{$this->altanativeSession}
            ->read($this->name)
        ;

        if($name){
            if(!empty($buffer[$name])){
                return $buffer[$name];
            }
        }
        else{
            return $buffer;
        }
    }

    /**
     * getPasswordHash
     * @params $passwordd
     */
    public function getPasswordHash($password){

        if(method_exists($this,"callbackPasswordHash")){
            return $this->callbackPasswordHash($password);
        }
        else{
            return $this->Backpack->{$this->altanativeEncrypt}
            ->hash($password,$this->hash);
        }

    }

    private function _makeToken($logined){
        $hash=$logined.$this->name;
        $hash=$this->Backpack->{$this->altanativeEncrypt}
            ->hash($hash,$this->hash);

        return $hash;
    }
    
}