package assn1
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"
	//"fmt"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)


func hashAppend(key string, value []byte) []byte {
	sha:=userlib.NewHMAC([]byte(key))
	sha.Write(append([]byte(key),value...))
	value=append(value,sha.Sum(nil)...)
	return value

}

func hashCheck(key string,value []byte) ([]byte, error){
	length:=len(value)
	storedhmac:=value[length-32:]
	value=value[:length-32]
	sha:=userlib.NewHMAC([]byte(key))
	sha.Write(append([]byte(key),value...))
	shaval:=sha.Sum(nil)
	for i:=0;i<=31;i++{
		if storedhmac[i]!=shaval[i]{
			return nil, errors.New("Integrity failed")
		}
	}
	return value,nil
	
} 

func privateKeyCrypto(msg string, key []byte) []byte{

	ciphertext := make([]byte, userlib.BlockSize+len(msg))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(16))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(msg))
	ciphertext=append(ciphertext,iv...)
	return ciphertext
}
func privateKeyDecrypt(key []byte, IV []byte, cipher []byte) []byte{
	message:=userlib.CFBDecrypter(key,IV)
	message.XORKeyStream(cipher[userlib.BlockSize:], cipher[userlib.BlockSize:])
	return cipher[userlib.BlockSize:]
}
// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())


	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("Ths an error")))


	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 5 
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}
type User struct {
	Username string
	Password string
	Pvtkey *userlib.PrivateKey
	Fnames map[string][]byte
	Owner map[string]bool
	Login bool
}

func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	if len(data)%configBlockSize!=0 {
		return errors.New("Block Size error")
	}
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	index := userlib.Argon2Key([]byte(userdata.Username),[]byte(userdata.Username),16)
	var encryptedData []byte
	_,BOOL:=userdata.Fnames[filename]
	if BOOL==true{
		_,BOOL:=userlib.DatastoreGet(string(userdata.Fnames[filename])+"meta")
		if BOOL==false{
			return errors.New("File Revoked")
		}
		shamatch:=true
		var shaval []byte
		fetchdata,_:=userlib.DatastoreGet(string(userdata.Fnames[filename])+userdata.Username+"Key")
		fetchdata,ERR:=hashCheck(string(userdata.Fnames[filename])+userdata.Username+"Key",fetchdata)
		if ERR!=nil{
			return errors.New("Integrity violated")
		}
		length:=len(fetchdata)
		FileKey:=fetchdata[:length-32]
		sha:= userlib.NewSHA256()
		sha.Write(FileKey)
		shaval=sha.Sum(nil)
		for j :=31;j>=0;j--{
	       	if fetchdata[length-j-1] != shaval[31-j] {
           		shamatch= false
           		break
       		}
   		}
   		if shamatch==true{
	   		length:=len(FileKey)
			IV:=FileKey[length-16:]
			FileKey=FileKey[:length-16]
   			FileKey=privateKeyDecrypt(argpassword,IV,FileKey)
   			numberofblocks:=len(data)/configBlockSize
			lents:=[2]byte{byte(numberofblocks%256),byte(numberofblocks/256)}
			VAR:=hashAppend(string(userdata.Fnames[filename])+"meta",lents[:])
			userlib.DatastoreSet(string(userdata.Fnames[filename])+"meta",VAR)
			sha= userlib.NewSHA256()
			for i:=0;i<numberofblocks;i++{
				encryptedData=privateKeyCrypto(string(data[i*configBlockSize:(i+1)*configBlockSize]),FileKey)
				sha= userlib.NewSHA256()
				sha.Write(encryptedData)
				encryptedData=append(encryptedData,sha.Sum(nil)...)
				encryptedData=hashAppend(string(userdata.Fnames[filename])+string(i),encryptedData)
				userlib.DatastoreSet(string(userdata.Fnames[filename])+string(i),encryptedData)
			}
			return nil
   		}else{
   			return errors.New("Integrity compromised")
   		}
   	}
	FileKey:=userlib.RandomBytes(16)
	argfilename := userlib.Argon2Key([]byte(filename),[]byte(filename),16)
	userdata.Fnames[filename]=append(argfilename,index...)
	userdata.Owner[filename]=true
	
	bytes,err:=json.Marshal(userdata)
	if err!=nil{
		return errors.New("Undefined error creeped in")
	}
	bytes=privateKeyCrypto(string(bytes),argpassword)
	sha:=userlib.NewSHA256()
	sha.Write(bytes)
	bytes=append(bytes,sha.Sum(nil)...)
	bytes=hashAppend(string(index),bytes)
	userlib.DatastoreSet(string(index),bytes)
	numberofblocks:=len(data)/configBlockSize
	lents:=[2]byte{byte(numberofblocks%256),byte(numberofblocks/256)}
	VAR:=hashAppend(string(userdata.Fnames[filename])+"meta",lents[:])
	userlib.DatastoreSet(string(userdata.Fnames[filename])+"meta",VAR)
	sha= userlib.NewSHA256()
	for i:=0;i<numberofblocks;i++{
		encryptedData=privateKeyCrypto(string(data[i*configBlockSize:(i+1)*configBlockSize]),FileKey)
		sha= userlib.NewSHA256()
		sha.Write(encryptedData)
		encryptedData=append(encryptedData,sha.Sum(nil)...)
		encryptedData=hashAppend(string(userdata.Fnames[filename])+string(i),encryptedData)
		userlib.DatastoreSet(string(userdata.Fnames[filename])+string(i),encryptedData)
	}
	FileKey=privateKeyCrypto(string(FileKey),argpassword)
	//FileKey,_=userlib.RSAEncrypt(&userdata.Pvtkey.PublicKey,FileKey,[]byte("tag"))
	sha= userlib.NewSHA256()
	sha.Write(FileKey)
	FileKey=append(FileKey,sha.Sum(nil)...)
	FileKey=hashAppend(string(userdata.Fnames[filename])+userdata.Username+"Key",FileKey)
	userlib.DatastoreSet(string(userdata.Fnames[filename])+userdata.Username+"Key",FileKey)
    return nil
}

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	shamatch:=true
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	numberofblocks:=len(data)/configBlockSize
	if len(data)%configBlockSize!=0 {
		return errors.New("Block Size error")
	}
	var encryptedData []byte
	argfilename,chk:= userdata.Fnames[filename]
	if chk==false{
		return errors.New("Invalid filename")
	}
	metafetch,BOOL:=userlib.DatastoreGet(string(argfilename)+"meta")
	if BOOL==false{
		return errors.New("Meta data could not be found")
	}
	metafetch,ERR:=hashCheck(string(argfilename)+"meta",metafetch)
	if ERR!=nil{
		return errors.New("Integrity violated")
	}
	metafetchint:=int(metafetch[len(metafetch)-1])*256+int(metafetch[len(metafetch)-2])
	for i:=0;i<metafetchint;i++{
		fetch,BOOL:=userlib.DatastoreGet(string(argfilename)+string(i))
		if BOOL==false{
			return errors.New("Unexpected error")
		}
		fetch,ERR:=hashCheck(string(argfilename)+string(i),fetch)
		if ERR!=nil{
			return errors.New("Integrity violated")
		}
		sha:=userlib.NewSHA256()
		length:=len(fetch)
		storedsha:=fetch[length-32:]
		sha.Write(fetch[:length-32])
		shaval:=sha.Sum(nil)
		for j:=0;j<=31;j++{
			if storedsha[j]!=shaval[j]{
				return errors.New("Integrity compromised")
			}
		}
	}




	bytes:=[2]byte{byte((metafetchint+numberofblocks)%256),byte((metafetchint+numberofblocks)/256)}
	metafetch=append(metafetch,bytes[:]...)
	metafetch=hashAppend(string(argfilename)+"meta",metafetch)
	userlib.DatastoreSet(string(argfilename)+"meta",metafetch)
	fetchdata,BOOL:=userlib.DatastoreGet(string(argfilename)+userdata.Username+"Key")
	if BOOL==false{
		errors.New("Undefined Error creeped in")
	}
	fetchdata,ERR=hashCheck(string(argfilename)+userdata.Username+"Key",fetchdata)
	if ERR!=nil{
		return errors.New("Mutation detected")
	}
	sha:=userlib.NewSHA256()
	length:=len(fetchdata)
	encryptedFileKey:=fetchdata[:length-32]
	storedsha:=fetchdata[length-32:]
	sha.Write(encryptedFileKey)
	shaval:=sha.Sum(nil)
	for j:=31;j>=0;j--{
		if shaval[j]!=storedsha[j]{
			shamatch=false
			break
		}
	}
	var FileKey []byte
	if shamatch==true{
		length:=len(encryptedFileKey)
		IV:=encryptedFileKey[length-16:]
		encryptedFileKey=encryptedFileKey[:length-16]
		FileKey=privateKeyDecrypt(argpassword,IV,encryptedFileKey)
		//FileKey,_ =userlib.RSADecrypt(userdata.Pvtkey,encryptedFileKey,[]byte("tag"))
	} else {
		return errors.New("Unexpected error")
	}
	for i:=metafetchint;i<metafetchint+numberofblocks;i++{
		encryptedData=privateKeyCrypto(string(data[(i-metafetchint)*configBlockSize:(i-metafetchint+1)*configBlockSize]),FileKey)
		sha= userlib.NewSHA256()
		sha.Write(encryptedData)
		encryptedData=append(encryptedData,sha.Sum(nil)...)
		encryptedData=hashAppend(string(argfilename)+string(i),encryptedData)
		userlib.DatastoreSet(string(argfilename)+string(i),encryptedData)
		
	}
	return nil
}


func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	shamatch:=true
	var shaval []byte
	argfilename := userdata.Fnames[filename]
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	metafetch,BOOL:=userlib.DatastoreGet(string(argfilename)+"meta")
	if BOOL==false{
		return nil, errors.New("File meta data could not be found")
	}
	metafetch,ERR:=hashCheck(string(argfilename)+"meta",metafetch)
	
	if ERR!=nil{
		return []byte(""),errors.New("Integrity violated")
	}
	metafetchint:=int(metafetch[len(metafetch)-1])*256+int(metafetch[len(metafetch)-2])
	if metafetchint-1<offset  || offset <0{
		//fmt.Println(metafetchint)
		return nil,errors.New("Out of bound access")
	}
	fetchdata,chk:=userlib.DatastoreGet(string(argfilename)+userdata.Username+"Key")
	if chk==false{
		return nil, errors.New("Invalid filename")
	}
	fetchdata,ERR=hashCheck(string(argfilename)+userdata.Username+"Key",fetchdata)
	if ERR!=nil{
		return []byte(""),errors.New("Integrity violated")
	}
	length:=len(fetchdata)
	FileKey:=fetchdata[:length-32]
	sha:= userlib.NewSHA256()
	sha.Write(FileKey)
	shaval=sha.Sum(nil)


	for j :=31;j>=0;j--{
       	if fetchdata[length-j-1] != shaval[31-j] {
           	shamatch= false
           	break
       	}
   	}
   	if shamatch==true{
   		length:=len(FileKey)
		IV:=FileKey[length-16:]
		FileKey=FileKey[:length-16]
   		FileKey=privateKeyDecrypt(argpassword,IV,FileKey)
   		//FileKey,_=userlib.RSADecrypt(userdata.Pvtkey,FileKey,[]byte("tag"))
   		i:=offset
			fetchdata,BOOL=userlib.DatastoreGet(string(argfilename)+string(i))
			if BOOL==false{
				return nil,errors.New("File Not Found")
			}
			fetchdata,ERR:=hashCheck(string(argfilename)+string(i),fetchdata)
			if ERR!=nil{
				return []byte(""),errors.New("Integrity violated")
			}
			
			length=len(fetchdata)

			encryptedData:=fetchdata[:length-32]
			sha= userlib.NewSHA256()
			sha.Write(encryptedData)
			shaval:=sha.Sum(nil)
			for j :=31;j>=0;j--{
	        	if fetchdata[length-j-1] != shaval[31-j] {
    	        	shamatch= false
        	    	break
        		}
    		}
			if shamatch==true{
				length:=len(encryptedData)
				IV:=encryptedData[length-16:]
				encryptedData=encryptedData[:length-16]
				return privateKeyDecrypt(FileKey,IV,encryptedData),nil
			}else{
				return nil, errors.New("Integrity compromised")
			}
	}	
	return nil,errors.New("unexpected error")
}


// ShareFile : Function used to the share file with other user

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	receiverPublicKey,BOOL:=userlib.KeystoreGet(recipient)
	if BOOL==false{
		return "",errors.New("Invalid recipient")
	}
	argfilename:=userdata.Fnames[filename]
	encryptedKey,BOOL:=userlib.DatastoreGet(string(userdata.Fnames[filename])+userdata.Username+"Key")
	if BOOL==false{
		return "",errors.New("invalid filename")
	}
	encryptedKey,ERR:=hashCheck(string(userdata.Fnames[filename])+userdata.Username+"Key",encryptedKey)
	if ERR!=nil{
		return "",errors.New("Integrity violated")
	}

	
	length:=len(encryptedKey)
	storedsha:=encryptedKey[length-32:]
	encryptedKey=encryptedKey[:length-32]
	sha:=userlib.NewSHA256()
	sha.Write(encryptedKey)
	shaval:=sha.Sum(nil)
	shamatch:=true
	for i:=0;i<32;i++{
		if shaval[i]!=storedsha[i]{
			shamatch=false
		}
	}
	if shamatch==false{
		return "",errors.New("Unexpected eror")
	}
	length=len(encryptedKey)
	IV:=encryptedKey[length-16:]
	encryptedKey=encryptedKey[:length-16]
	decryptedKey:=privateKeyDecrypt(argpassword,IV,encryptedKey)
	//decryptedKey,_:=userlib.RSADecrypt(userdata.Pvtkey,encryptedKey,[]byte("tag"))
	share:=sharingRecord{Filename:argfilename, Key:decryptedKey}
	bytes,err:=json.Marshal(share)
	if err!=nil{
		return "",errors.New("Undefined error creeped in")
	}
	bytes,err=userlib.RSAEncrypt(&receiverPublicKey,bytes,[]byte("tag"))
	if err!=nil{
		return "",errors.New("Undefined error creeped in")
	}
	signature,err:=userlib.RSASign(userdata.Pvtkey,bytes)
	bytes=append(bytes,signature...)
	bytes=hashAppend(string(argfilename)+recipient,bytes)
	userlib.DatastoreSet(string(argfilename)+recipient,bytes)
	return string(argfilename)+recipient,nil
}

func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	senderPublic,BOOL:=userlib.KeystoreGet(sender)
	if BOOL==false{
		return errors.New("invalid msgid")
	}
	bytes,BOOL:=userlib.DatastoreGet(msgid)
	if BOOL==false{
		return errors.New("invalid msgid")
	}
	bytes,ERR:=hashCheck(msgid,bytes)
	if ERR!=nil{
		return errors.New("Integrity violated")
	}
	length:=len(bytes)
	signature:=bytes[length-256:]
	bytes=bytes[:length-256]
	err:=userlib.RSAVerify(&senderPublic,bytes,signature)
	if err!=nil{
		return errors.New("Invalid signature")
	}
	bytes,err=userlib.RSADecrypt(userdata.Pvtkey,bytes,[]byte("tag"))
	if err!=nil{
		return errors.New("Invalid Private Key")
	}
	var share sharingRecord
	json.Unmarshal(bytes,&share)
	json.Unmarshal(bytes,&share)
	for _, v := range userdata.Fnames{
		leng:=len(v)
		for p:=0;p<leng;p++{
			if v[p]!=share.Filename[p]{
				continue
			}
			if p==leng-1{
				return errors.New("File Received already")
			}
		}
	}
	userdata.Fnames[filename]=share.Filename
	//fmt.Println("OKAY",share.Filename)
	userdata.Owner[filename]=false
	FileKey:=share.Key
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	FileKey=privateKeyCrypto(string(FileKey),argpassword)
	//FileKey,_=userlib.RSAEncrypt(&userdata.Pvtkey.PublicKey,FileKey,[]byte("tag"))
	sha:= userlib.NewSHA256()
	sha.Write(FileKey)
	FileKey=append(FileKey,sha.Sum(nil)...)
	FileKey=hashAppend(string(userdata.Fnames[filename])+userdata.Username+"Key",FileKey)
	userlib.DatastoreSet(string(userdata.Fnames[filename])+userdata.Username+"Key",FileKey)
	//metafetch,BOOL:=userlib.DatastoreGet(string(userdata.Fnames[filename])+"meta")
	//fmt.Println(metafetch)
	index := userlib.Argon2Key([]byte(userdata.Username),[]byte(userdata.Username),16)
	bytes,_=json.Marshal(userdata)
	encryptedUserdata:=privateKeyCrypto(string(bytes),argpassword)
	sha=userlib.NewSHA256()
	sha.Write(encryptedUserdata)
	encryptedUserdata=append(encryptedUserdata,sha.Sum(nil)...)
	encryptedUserdata=hashAppend(string(index),encryptedUserdata)
	userlib.DatastoreSet(string(index),encryptedUserdata)
	return nil
}


// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	var myfile []byte
	fname:=userdata.Fnames[filename]
	if userdata.Owner[filename]==false{
		return errors.New("Not the owner of the file")
	}
	metafetch,BOOL:=userlib.DatastoreGet(string(fname)+"meta")
	if BOOL==false{
		return errors.New("The file metadata not found")
	}
	metafetch,ERR:=hashCheck(string(fname)+"meta",metafetch)
	if ERR!=nil{
		return errors.New("Integrity violated")
	}
	metafetchint:=int(metafetch[len(metafetch)-1])*256+int(metafetch[len(metafetch)-2])
	for i:=0;i<metafetchint;i++{
		bytes,_:=userdata.LoadFile(filename,i)
		userlib.DatastoreDelete(string(fname)+string(i))
		myfile=append(myfile,bytes...)
	}
	userlib.DatastoreDelete(string(fname)+"meta")
	var encryptedData []byte
	FileKey:=userlib.RandomBytes(16)
	fname =append(fname,byte(1))
	userdata.Fnames[filename]=fname
	index := userlib.Argon2Key([]byte(userdata.Username),[]byte(userdata.Username),16)
	argpassword:=userlib.Argon2Key([]byte(userdata.Password),[]byte(userdata.Password),16)
	bytes,err:=json.Marshal(userdata)
	if err!=nil{
		return errors.New("Unknown error creeped in")
	}
	bytes=privateKeyCrypto(string(bytes),argpassword)
	sha:=userlib.NewSHA256()
	sha.Write(bytes)
	bytes=append(bytes,sha.Sum(nil)...)
	//fmt.Println("Is it here")
	bytes=hashAppend(string(index),bytes)
	userlib.DatastoreSet(string(index),bytes)
	//fmt.Println("Or Is it here")
	numberofblocks:=len(myfile)/configBlockSize
	lents:=[2]byte{byte(numberofblocks%256),byte(numberofblocks/256)}
	VAR:=hashAppend(string(fname)+"meta",lents[:])
	userlib.DatastoreSet(string(fname)+"meta",VAR)
	sha= userlib.NewSHA256()
	for i:=0;i<numberofblocks;i++{
		encryptedData=privateKeyCrypto(string(myfile[i*configBlockSize:(i+1)*configBlockSize]),FileKey)
		sha= userlib.NewSHA256()
		sha.Write(encryptedData)
		encryptedData=append(encryptedData,sha.Sum(nil)...)
		encryptedData=hashAppend(string(fname)+string(i),encryptedData)
		userlib.DatastoreSet(string(fname)+string(i),encryptedData)
	}
	FileKey=privateKeyCrypto(string(FileKey),argpassword)
	//FileKey,_=userlib.RSAEncrypt(&userdata.Pvtkey.PublicKey,FileKey,[]byte("tag"))
	sha= userlib.NewSHA256()
	sha.Write(FileKey)
	FileKey=append(FileKey,sha.Sum(nil)...)
	FileKey=hashAppend(string(fname)+userdata.Username+"Key",FileKey)
	userlib.DatastoreSet(string(fname)+userdata.Username+"Key",FileKey)
    return nil
}
type sharingRecord struct {
	Filename []byte
	Key []byte
}

func InitUser(username string, password string) (*User, error) {
	var err1 error
	var err2 error
	if username=="" || password==""{
		return nil,errors.New("Weak credentials")
	}
	pvtkey,err1 := userlib.GenerateRSAKey()
	_,BOOL:=userlib.KeystoreGet(username)
	if BOOL==true{
		return nil, errors.New("Duplicate user")
	}
	userlib.KeystoreSet(username,pvtkey.PublicKey)
	index := userlib.Argon2Key([]byte(username),[]byte(username),16)
	argpassword:=userlib.Argon2Key([]byte(password),[]byte(password),16)
	userdataptr:= User{Username:username,Password:password,Pvtkey:pvtkey, Fnames: make(map[string][]byte), Owner:make(map[string]bool),Login:false}
	bytes,err2:=json.Marshal(userdataptr)
	encryptedUserdata:=privateKeyCrypto(string(bytes),argpassword)
	sha:=userlib.NewSHA256()
	sha.Write(encryptedUserdata)
	encryptedUserdata=append(encryptedUserdata,sha.Sum(nil)...)
	encryptedUserdata=hashAppend(string(index),encryptedUserdata)
	userlib.DatastoreSet(string(index),encryptedUserdata)
	if err1==nil && err2==nil{
		return &userdataptr,nil
	} else{
		return nil,errors.New("Unexpected error")
	}
}


func GetUser(username string, password string) (*User, error) {
	var bytes []byte
	var BOOL bool
	var userdataptr User
	index:=userlib.Argon2Key([]byte(username),[]byte(username),16)
	argpassword:=userlib.Argon2Key([]byte(password),[]byte(password),16)
	bytes,BOOL=userlib.DatastoreGet(string(index))
	if BOOL==false{
		//.Println("BWAHAHAHA")
			return nil,errors.New("Invalid User")
		}
	bytes,ERR:=hashCheck(string(index),bytes)
	if ERR!=nil{
		return nil,errors.New("Integrity violated")
	}
	length:=len(bytes)
	shamatch:=true
	storedsha:=bytes[length-32:]
	sha:=userlib.NewSHA256()
	sha.Write(bytes[:length-32])
	shaval:=sha.Sum(nil)
	for i:=0;i<=31;i++{
		if shaval[i]!=storedsha[i]{
			shamatch=false
			break
		}
	}
	if shamatch==true{
		bytes=bytes[:length-32]
		length=len(bytes)
		IV:=bytes[length-16:]
		bytes=bytes[:length-16]
		bytes=privateKeyDecrypt([]byte(argpassword),IV,bytes)
		json.Unmarshal(bytes,&userdataptr)
		if userdataptr.Login==false{
			userdataptr.Login=true
			bytes,_=json.Marshal(userdataptr)
			encryptedUserdata:=privateKeyCrypto(string(bytes),argpassword)
			sha=userlib.NewSHA256()
			sha.Write(encryptedUserdata)
			encryptedUserdata=append(encryptedUserdata,sha.Sum(nil)...)
			encryptedUserdata=hashAppend(string(index),encryptedUserdata)
			userlib.DatastoreSet(string(index),encryptedUserdata)
			return &userdataptr,nil	

		}else{
			return nil,errors.New("Multiple login not allowed")
		}
		
	}else{
		return nil,errors.New("Integrity violated")
	}
	
}
