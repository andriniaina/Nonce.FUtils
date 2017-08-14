
namespace NonceUtil
module NonceUtil =
    open System
    open System.Text
    open System.Security.Cryptography

    let private SALT_MINE = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM&'(-_)=~#{[|`\^@]}^¨$£¤*µ%ù!§:/;.?<>²".ToCharArray()
    let private rand = new Random()
    let private unix0 = new DateTime(1970, 1, 1)

    let private asUTF8Bytes (s:string) = Encoding.UTF8.GetBytes s
    let private asBase64 = Convert.ToBase64String

    let private generateRandomSalt (r:Random) =
        let SALT_LENGTH = 15
        let charGenerator =
            let nbChars = SALT_MINE.Length - 1
            seq {
              for i in 0..SALT_LENGTH-1 do yield SALT_MINE.[r.Next(0, nbChars)]
            }
        
        charGenerator |> Seq.toArray |> String
  
    let private secondsFromNowSinceUnix0 (secondsToAdd:int) :int =
        let expiration = DateTime.UtcNow.AddSeconds(float secondsToAdd)
        (expiration - unix0).TotalSeconds |> int


    let private computeHash (plainText:byte array) (salt:byte array) (timeout:byte array) =
        use sha256 = new SHA256Managed();
        [ plainText ; salt ; timeout ]
            |> Seq.concat
            |> Seq.toArray
            |> sha256.ComputeHash
            |> asBase64

    let private generateNonce (secret:string) (nonceTimeoutSeconds) =
        if String.IsNullOrEmpty(secret) || secret.Length<=10 then raise (new ArgumentException("secret")) else
        if nonceTimeoutSeconds=0 then raise (new ArgumentException("nonceTimeoutSeconds")) else
        
        let salt = generateRandomSalt rand
        let timeout = nonceTimeoutSeconds |> secondsFromNowSinceUnix0
        
        let encodedSalt = salt |> asUTF8Bytes
        let encodedSecret = secret |> asUTF8Bytes
        let encodedTimeout = timeout.ToString() |> asUTF8Bytes
        let hash = computeHash encodedSalt encodedSecret encodedTimeout
        
        sprintf "%s,%i,%s" salt timeout hash

    let private validateFormat (salt,nonceTimeoutSeconds,hash) =
        let isNotNullOrEmpty = String.IsNullOrEmpty >> not
        let isInteger s =
            let success,doubleValue = Int32.TryParse(s)
            success
        
        isNotNullOrEmpty salt && isNotNullOrEmpty nonceTimeoutSeconds && isNotNullOrEmpty hash && isInteger nonceTimeoutSeconds

      
    let private checkHash (secret:string) (salt,nonceTimeoutSeconds,hash) =
        let encodedSalt = salt |> asUTF8Bytes
        let encodedSecret = secret |> asUTF8Bytes
        let encodedTimeout = nonceTimeoutSeconds |> asUTF8Bytes
        let isExpired = secondsFromNowSinceUnix0 0 > int(nonceTimeoutSeconds) 
        not isExpired && hash = computeHash encodedSalt encodedSecret encodedTimeout

    let private checkNonce secret nonce =
        if String.IsNullOrEmpty secret then raise (new ArgumentException("secret")) else
        if String.IsNullOrEmpty nonce then raise (new ArgumentException("nonce")) else
        
        match nonce.Split(',') with
            |  [|salt; nonceTimeoutSeconds; hash|] -> validateFormat (salt,nonceTimeoutSeconds,hash) && checkHash secret (salt,nonceTimeoutSeconds,hash)
            | _ -> false
    
    // public methods for C# libs
    let GenerateNonce (secret:string, nonceTimeoutSeconds) = generateNonce secret nonceTimeoutSeconds
    let CheckNonce (secret ,nonce )= checkNonce secret nonce
    let GenerateSalt() = generateRandomSalt rand

