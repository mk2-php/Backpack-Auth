<?php

namespace mk2\backpack_auth;

use Mk2\Libraries\Backpack;
use mk2\backpack_encrypt\EncryptBackpack;

class AuthBackpack extends Backpack{

    public $name="userAuthority";

    public $table="User";

    public $colum=[
        "username"=>"username",
        "password"=>"password",
    ];

	public $encrypt=[
		"encAlgolizum"=>"aes-256-cbc",
		"encSalt"=>"mk2usrauthoritysalt23456789********************************",
		"encPassword"=>"mk2usrauthoritypassword123456789*****************************",
	];
		
	/**
	 * __construct
	 */
	public function __construct(){
		parent::__construct();
		
		if(!empty($this->alternativeEncrypt)){
			$this->Encrypt=new $this->alternativeEncrypt();
		}
		else{
			$this->Encrypt=new EncryptBackpack();
        }

        if(!$this->Table->exists($this->table)){
            throw new \Exception("authority table '".$this->table."Table' not found..");
        }
        $this->Table->load($this->table);

    }

    public function verify($post){

print_r($post);
        exit;

    }

	
}