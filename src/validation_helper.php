<?php
defined('BASEPATH') OR exit('No direct script access allowed');

    //<editor-fold desc="Validation data">
	function validate_time($time) {
	    return preg_match("/^(?:2[0-3]|[01][0-9]):[0-5][0-9]$/", $time);
    }

    function validate_color($color) {
	    return preg_match('/#([a-f0-9]{3}){1,2}\b/i',$color);
    }

    function validate_boolean($data) {
        return filter_var($data, FILTER_VALIDATE_BOOLEAN);
    }

	function validate_string($data,$min_length = 3,$latin = FALSE) {

	    $data   =   trim($data);

        if (strlen($data) < $min_length)
            return FALSE;
        else
            return TRUE;

	}
	
	function validate_username($data) {
		return preg_match('/^[0-9a-zA-Z\.]+$/', $data);
	}
	
	function validate_email($data) {
		return filter_var($data,FILTER_VALIDATE_EMAIL);
	}

    function validate_url($data) {
        return filter_var($data,FILTER_VALIDATE_URL);
    }

    function validate_range($data,$from,$to = NULL) {

	    if (!validate_number($data))
	        return FALSE;


		if ($from != NULL && $to == NULL) {
			if ($data >= $from)
				return TRUE;
			else
				return FALSE;
		}

	    if ($data >= $from && $data <= $to)
	        return TRUE;

	    return FALSE;

    }

	function validate_int($data) {
		return boolval(preg_match('/^\b\d*\.?\d+(?=|$)$/',$data));
	}

	function validate_float($data) {
	    return filter_var($data,FILTER_VALIDATE_FLOAT);
    }
	
	function validate_number($data) {
		return validate_int($data);
	}

	//check characters is number only
	function validate_numbers($data) {
	    return validate_int($data);
    }

	//at least password is 5 character
	function validate_password($data) {
		return preg_match('/^[\S|\s]{5,}$/',$data);
	}

	function validate_phone($phone) {
		  return preg_match("/^0[0-9]{8,15}$/",$phone);
	}

    function validate_phone_ir($phone) {
        return preg_match("/^0[0-9]{10}$/",$phone);
    }
	
	function valid_phone($phone) {
		  return validate_phone($phone);   
	}
	
	function validate_date($date,$separator ='/') {
		return preg_match("|^\d{4}$separator\d{1,2}$separator\d{1,2}$|",$date);
	}

    function validate_location($location,$output = FALSE) {

	    if ($location == '') return FALSE;

        if (!preg_match("/^(((-?)\d+\.\d+)|(-?)\d+),(((-?)\d+\.\d+)|(-?)\d+)/",str_replace(' ','',$location)))
            return FALSE;
        else {
            if ($output == FALSE) return TRUE;
            return explode(',',$location);
        }
    }

    function validate_json_array($data) {

	    if (json_decode($data) == FALSE)
	        return FALSE;

	    $res    =   json_decode($data);
	    if (is_array($res))
	        return TRUE;
	    else
	        return FALSE;

    }

    function validate_json_object($data) {

        if (json_decode($data) == FALSE)
            return FALSE;

        $res    =   json_decode($data);
        if (!is_array($res))
            return TRUE;
        else
            return FALSE;

    }

	function validate_audio($path,$get_duration = FALSE) {
			
		$mp3file = new MP3File($path);
		$duration1 = $mp3file->getDurationEstimate();//(faster) for CBR only

		//$duration2 = $mp3file->getDuration();//(slower) for VBR (or CBR)
		if (filter_var($duration1,FILTER_VALIDATE_INT))
			return $get_duration ? $duration1 : TRUE;
		else
			return FALSE;
    }

    function validate_picture_size($path,$width,$height,$op) {

        $is_picture	= getimagesize($path);
        if ($is_picture === FALSE) return FALSE;

        if ($op	==	'>') {
            if ($is_picture[0] > $width && $is_picture[1] > $height)
                return TRUE;
            else
                return FALSE;
        } else if ($op	==	'<') {
            if ($is_picture[0] < $width && $is_picture[1] < $height)
                return TRUE;
            else
                return FALSE;
        } else if ($op	==	'=') {
            if ($is_picture[0] == $width && $is_picture[1] == $height)
                return TRUE;
            else
                return FALSE;
        }

    }

    function validate_picture_type($path,$type) {

        $picture_type	=	exif_imagetype($path);

        switch(strtolower($type)) {
            case "gif":
                if ($picture_type	!=	IMAGETYPE_GIF) return FALSE;
                break;

            case "jpg":
            case "jpeg":
                if ($picture_type	!=	IMAGETYPE_JPEG) return FALSE;
                break;

            case "png":
                if ($picture_type	!=	IMAGETYPE_PNG) return FALSE;
                break;
        }

        return TRUE;

    }

    function validate_video($filename) {

        $extension	=	get_mime($filename);

        if(strpos($extension,'mp4') !== FALSE)
            return TRUE;
        else
            return FALSE;

    }

    function validate_upload_filesize($path,$size) {

        if (filesize($path) > $size)
            return FALSE;
        else
            return TRUE;

    }

    function validate_upload($key_name,$is_image = TRUE) {

        if (empty($_FILES))											return FALSE;
        if (!isset($_FILES[$key_name]))								return FALSE;
        if ($_FILES[$key_name]['error']	!=	0)						return FALSE;
        if ($_FILES[$key_name]['size']	==	0)						return FALSE;
        if (!is_uploaded_file($_FILES[$key_name]['tmp_name']))		return FALSE;
        if (!file_exists($_FILES[$key_name]['tmp_name']))			return FALSE;

        if ($is_image	==	TRUE) {

            $file_type	=	$_FILES[$key_name]['type'];

            //if (strpos($file_type,'image')	===	FALSE) 				return FALSE;
            if (!validate_picture($_FILES[$key_name]['tmp_name']))	return FALSE;

            return TRUE;

        } else {
            return TRUE;
        }

    }

    function validate_zip($filename) {

        if(is_resource($zip = zip_open($filename))) {
            zip_close($zip);
            return TRUE;
        }
        else {
            return FALSE;
        }

    }

    function validate_base64_picture($base64) {

		$img = @imagecreatefromstring(base64_decode($base64));
		if (!$img) {
			return false;
		}

		imagepng($img, 'tmp.png');
		$info = getimagesize('tmp.png');

		$file_size  =   @filesize('tmp.png');

		unlink('tmp.png');

		if ($info[0] > 0 && $info[1] > 0 && $info['mime']) {
			$info['size']   =   $file_size;
			return $info;
		}

		return false;

	}

    function validate_imei($imei){

		// Should be 15 digits
		if(strlen($imei) != 15 || !ctype_digit($imei))
			return false;
		// Get digits
		$digits = str_split($imei);
		// Remove last digit, and store it
		$imei_last = array_pop($digits);
		// Create log
		$log = array();
		// Loop through digits
		foreach($digits as $key => $n){
			// If key is odd, then count is even
			if($key & 1){
				// Get double digits
				$double = str_split($n * 2);
				// Sum double digits
				$n = array_sum($double);
			}
			// Append log
			$log[] = $n;
		}
		// Sum log & multiply by 9
		$sum = array_sum($log) * 9;
		// Compare the last digit with $imei_last
		return substr($sum, -1) == $imei_last;

	}

	function validate_localhost() {

	    $ci = & get_instance();

	    $ip = $ci->input->ip_address();

	    return ($ip == 'localhost' || $ip == '127.0.0.1' || $ip == '::');

    }
	
	function is_apple_platform() {

        $iPod    = stripos($_SERVER['HTTP_USER_AGENT'],"iPod");
        $iPhone  = stripos($_SERVER['HTTP_USER_AGENT'],"iPhone");
        $iPad    = stripos($_SERVER['HTTP_USER_AGENT'],"iPad");
        $Android = stripos($_SERVER['HTTP_USER_AGENT'],"Android");
        $webOS   = stripos($_SERVER['HTTP_USER_AGENT'],"webOS");

        if( $iPod || $iPhone ){
            return TRUE;
        }else if($iPad){
            return TRUE;
        }else if($Android){
            return TRUE;
        }else if($webOS){
            return TRUE;
        }

        return FALSE;

    }

	function validate_null($data = array()) {

		foreach ($data as $key => $value) {
			if (!is_array($value))
				if ($value == '' || $value == NULL)
					return  FALSE;
		}

		return TRUE;

	}
	
	function is_complex_password($password) {
    // check if the password has at least 8 characters
    if (strlen($password) < 8) {
        return false;
    }

    // check if the password has a uppercase letter
    if (!preg_match('/[A-Z]/', $password)) {
        return false;
    }

    // check if the password has a lowercase letter
    if (!preg_match('/[a-z]/', $password)) {
        return false;
    }

    // check if the password has a number
    if (!preg_match('/\d/', $password)) {
        return false;
    }

    // check if the password has a special character
    if (!preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
        return false;
    }

    // the password is complex
    return true;
}
	
	class MP3File
{
    protected $filename;
    public function __construct($filename)
    {
        $this->filename = $filename;
    }
 
    public static function formatTime($duration) //as hh:mm:ss
    {
        //return sprintf("%d:%02d", $duration/60, $duration%60);
        $hours = floor($duration / 3600);
        $minutes = floor( ($duration - ($hours * 3600)) / 60);
        $seconds = $duration - ($hours * 3600) - ($minutes * 60);
        return sprintf("%02d:%02d:%02d", $hours, $minutes, $seconds);
    }
 
    //Read first mp3 frame only...  use for CBR constant bit rate MP3s
    public function getDurationEstimate()
    {
        return $this->getDuration($use_cbr_estimate=true);
    }
 
    //Read entire file, frame by frame... ie: Variable Bit Rate (VBR)
    public function getDuration($use_cbr_estimate=false)
    {
        $fd = fopen($this->filename, "rb");
 
        $duration=0;
        $block = fread($fd, 100);
        $offset = $this->skipID3v2Tag($block);
        fseek($fd, $offset, SEEK_SET);
        while (!feof($fd))
        {
            $block = fread($fd, 10);
            if (strlen($block)<10) { break; }
            //looking for 1111 1111 111 (frame synchronization bits)
            else if ($block[0]=="\xff" && (ord($block[1])&0xe0) )
            {
                $info = self::parseFrameHeader(substr($block, 0, 4));
                if (empty($info['Framesize'])) { return $duration; } //some corrupt mp3 files
                fseek($fd, $info['Framesize']-10, SEEK_CUR);
                $duration += ( $info['Samples'] / $info['Sampling Rate'] );
            }
            else if (substr($block, 0, 3)=='TAG')
            {
                fseek($fd, 128-10, SEEK_CUR);//skip over id3v1 tag size
            }
            else
            {
                fseek($fd, -9, SEEK_CUR);
            }
            if ($use_cbr_estimate && !empty($info))
            { 
                return $this->estimateDuration($info['Bitrate'],$offset); 
            }
        }
        return round($duration);
    }
 
    private function estimateDuration($bitrate,$offset)
    {
        $kbps = ($bitrate*1000)/8;
        $datasize = filesize($this->filename) - $offset;
        return @round($datasize / $kbps);
    }
 
    private function skipID3v2Tag(&$block)
    {
        if (substr($block, 0,3)=="ID3")
        {
            $id3v2_major_version = ord($block[3]);
            $id3v2_minor_version = ord($block[4]);
            $id3v2_flags = ord($block[5]);
            $flag_unsynchronisation  = $id3v2_flags & 0x80 ? 1 : 0;
            $flag_extended_header    = $id3v2_flags & 0x40 ? 1 : 0;
            $flag_experimental_ind   = $id3v2_flags & 0x20 ? 1 : 0;
            $flag_footer_present     = $id3v2_flags & 0x10 ? 1 : 0;
            $z0 = ord($block[6]);
            $z1 = ord($block[7]);
            $z2 = ord($block[8]);
            $z3 = ord($block[9]);
            if ( (($z0&0x80)==0) && (($z1&0x80)==0) && (($z2&0x80)==0) && (($z3&0x80)==0) )
            {
                $header_size = 10;
                $tag_size = (($z0&0x7f) * 2097152) + (($z1&0x7f) * 16384) + (($z2&0x7f) * 128) + ($z3&0x7f);
                $footer_size = $flag_footer_present ? 10 : 0;
                return $header_size + $tag_size + $footer_size;//bytes to skip
            }
        }
        return 0;
    }
 
    public static function parseFrameHeader($fourbytes)
    {
        static $versions = array(
            0x0=>'2.5',0x1=>'x',0x2=>'2',0x3=>'1', // x=>'reserved'
        );
        static $layers = array(
            0x0=>'x',0x1=>'3',0x2=>'2',0x3=>'1', // x=>'reserved'
        );
        static $bitrates = array(
            'V1L1'=>array(0,32,64,96,128,160,192,224,256,288,320,352,384,416,448),
            'V1L2'=>array(0,32,48,56, 64, 80, 96,112,128,160,192,224,256,320,384),
            'V1L3'=>array(0,32,40,48, 56, 64, 80, 96,112,128,160,192,224,256,320),
            'V2L1'=>array(0,32,48,56, 64, 80, 96,112,128,144,160,176,192,224,256),
            'V2L2'=>array(0, 8,16,24, 32, 40, 48, 56, 64, 80, 96,112,128,144,160),
            'V2L3'=>array(0, 8,16,24, 32, 40, 48, 56, 64, 80, 96,112,128,144,160),
        );
        static $sample_rates = array(
            '1'   => array(44100,48000,32000),
            '2'   => array(22050,24000,16000),
            '2.5' => array(11025,12000, 8000),
        );
        static $samples = array(
            1 => array( 1 => 384, 2 =>1152, 3 =>1152, ), //MPEGv1,     Layers 1,2,3
            2 => array( 1 => 384, 2 =>1152, 3 => 576, ), //MPEGv2/2.5, Layers 1,2,3
        );
        //$b0=ord($fourbytes[0]);//will always be 0xff
        $b1=ord($fourbytes[1]);
        $b2=ord($fourbytes[2]);
        $b3=ord($fourbytes[3]);
 
        $version_bits = ($b1 & 0x18) >> 3;
        $version = $versions[$version_bits];
        $simple_version =  ($version=='2.5' ? 2 : $version);
 
        $layer_bits = ($b1 & 0x06) >> 1;
        $layer = $layers[$layer_bits];
 
        $protection_bit = ($b1 & 0x01);
        $bitrate_key = sprintf('V%dL%d', $simple_version , $layer);
        $bitrate_idx = ($b2 & 0xf0) >> 4;
        $bitrate = isset($bitrates[$bitrate_key][$bitrate_idx]) ? $bitrates[$bitrate_key][$bitrate_idx] : 0;
 
        $sample_rate_idx = ($b2 & 0x0c) >> 2;//0xc => b1100
        $sample_rate = isset($sample_rates[$version][$sample_rate_idx]) ? $sample_rates[$version][$sample_rate_idx] : 0;
        $padding_bit = ($b2 & 0x02) >> 1;
        $private_bit = ($b2 & 0x01);
        $channel_mode_bits = ($b3 & 0xc0) >> 6;
        $mode_extension_bits = ($b3 & 0x30) >> 4;
        $copyright_bit = ($b3 & 0x08) >> 3;
        $original_bit = ($b3 & 0x04) >> 2;
        $emphasis = ($b3 & 0x03);
 
        $info = array();
        $info['Version'] = $version;//MPEGVersion
        $info['Layer'] = $layer;
        //$info['Protection Bit'] = $protection_bit; //0=> protected by 2 byte CRC, 1=>not protected
        $info['Bitrate'] = $bitrate;
        $info['Sampling Rate'] = $sample_rate;
        //$info['Padding Bit'] = $padding_bit;
        //$info['Private Bit'] = $private_bit;
        //$info['Channel Mode'] = $channel_mode_bits;
        //$info['Mode Extension'] = $mode_extension_bits;
        //$info['Copyright'] = $copyright_bit;
        //$info['Original'] = $original_bit;
        //$info['Emphasis'] = $emphasis;
        $info['Framesize'] = self::framesize($layer, $bitrate, $sample_rate, $padding_bit);
        $info['Samples'] = @$samples[$simple_version][$layer];
        return $info;
    }
 
    private static function framesize($layer, $bitrate,$sample_rate,$padding_bit)
    {
        if ($layer==1)
            return intval(((12 * $bitrate*1000 /$sample_rate) + $padding_bit) * 4);
        else //layer 2, 3
            return @intval(((144 * $bitrate*1000)/$sample_rate) + $padding_bit);
    }
}