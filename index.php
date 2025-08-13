<?php //12.08.2025 Efe Arda YAMAK TÜBİTAK-BİLGEM...
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $validCountries = [
        "AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ","BS","BH","BD","BB","BY","BE","BZ","BJ",
        "BM","BT","BO","BQ","BA","BW","BV","BR","IO","BN","BG","BF","BI","CV","KH","CM","CA","KY","CF","TD","CL","CN","CX","CC",
        "CO","KM","CG","CD","CK","CR","CI","HR","CU","CW","CY","CZ","DK","DJ","DM","DO","EC","EG","SV","GQ","ER","EE","ET","FK",
        "FO","FJ","FI","FR","GF","PF","TF","GA","GM","GE","DE","GH","GI","GR","GL","GD","GP","GU","GT","GG","GN","GW","GY","HT",
        "HM","VA","HN","HK","HU","IS","IN","ID","IR","IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI","KP","KR","KW",
        "KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MK","MG","MW","MY","MV","ML","MT","MH","MQ","MR","MU","YT","MX",
        "FM","MD","MC","MN","ME","MS","MA","MZ","MM","NA","NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MP","NO","OM","PK",
        "PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR","QA","RE","RO","RU","RW","BL","SH","KN","LC","MF","PM","VC","WS",
        "SM","ST","SA","SN","RS","SC","SL","SG","SX","SK","SI","SB","SO","ZA","GS","SS","ES","LK","SD","SR","SJ","SZ","SE","CH",
        "SY","TW","TJ","TZ","TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","US","UM","UY","UZ","VU",
        "VE","VN","VG","VI","WF","EH","YE","ZM","ZW"
    ];
    $validCommonname = [".com", ".net", ".org", ".edu", ".gov", ".tr", ".io", ".co", ".info", ".biz", ".tel", ".de", ".xxx", ".eu", ".it", ".pro", ".ru", ".ac", ".ag", ".as", ".me", ".sg"];

    $errors = [];
    $required_fields = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'key_size', 'hash_alg'];
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $errors[] = "Eksik alan: $field";
        }
    }
    if (empty($errors)) {
        $country = strtoupper(trim($_POST["C"]));
        if (!in_array($country, $validCountries)) {
            $errors[] = "Geçersiz ülke kodu! Lütfen geçerli iki harfli ISO ülke kodu giriniz.";
        }

        $cn = strtolower(trim($_POST["CN"]));
        $isValidCN = false;
        foreach ($validCommonname as $suffix) {
            if (substr($cn, -strlen($suffix)) === $suffix) {
                $isValidCN = true;
                break;
            }
        }
        if (!$isValidCN) {
            $errors[] = "Geçersiz alan adı! Sadece şu uzantılar kabul ediliyor: " . implode(", ", $validCommonname);
        }

        $key_size = intval($_POST["key_size"]);
        if (!in_array($key_size, [2048, 4096])) {
            $errors[] = "Geçersiz anahtar boyutu!";
        }

        $valid_hashes = ["sha1", "sha256", "sha384", "sha512"];
        $hash_alg = strtolower($_POST["hash_alg"]);
        if (!in_array($hash_alg, $valid_hashes)) {
            $errors[] = "Geçersiz hash algoritması!";
        }
    }

    if (empty($errors)) {
        $config_path = realpath("C:/xampp/php/extras/openssl/openssl.cnf");
        if (!$config_path || !file_exists($config_path)) {
            $errors[] = "OpenSSL yapılandırma dosyası bulunamadı!";
        } else {
            $config = [
                "digest_alg" => $hash_alg,
                "private_key_bits" => $key_size,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
                "config" => $config_path
            ];

            $dn = [
                "commonName" => $_POST["CN"],                
                "organizationName" => $_POST["O"],
                "organizationalUnitName" => $_POST["OU"],
                "stateOrProvinceName" => $_POST["ST"],
                "localityName" => $_POST["L"],
                "countryName" => $country
                
            ];

            $privkey = openssl_pkey_new($config);
            if (!$privkey) {
                $errors[] = "Özel anahtar oluşturulamadı: " . openssl_error_string();
            } else {
                $csr = openssl_csr_new($dn, $privkey, $config);
                if (!$csr) {
                    $errors[] = "CSR oluşturulamadı: " . openssl_error_string();
                } else {
                    if (!openssl_pkey_export($privkey, $pkeyout, null, $config)) {
                        $errors[] = "Anahtar dışa aktarılamadı: " . openssl_error_string();
                    }
                    if (!openssl_csr_export($csr, $csrout)) {
                        $errors[] = "CSR dışa aktarılamadı: " . openssl_error_string();
                    }
                }
            }
        }
    }
    if (empty($errors)) {
        echo "<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'><title>CSR ve Anahtar</title>";
        echo "<style>
        @font-face {
            font-family: poppins;
            src: url('font/Poppins-Regular.ttf') format('truetype');
        }
        body {
            font-family: poppins; 
            padding: 20px; 
            background: #f0f0f0; 
            text-align: center;
        }
        h2, h3 { 
            color: #4CAF50; 
        }
        pre { 
            background: white; 
            padding: 15px; 
            border-radius: 8px; 
            overflow-x: auto; 
            text-align: left; 
            display: inline-block;
            max-width: 90vw;
            margin-left: auto;
            margin-right: auto;
        }
        a.button {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            z-index: 1000;
        }
        a.button:hover {
            background-color: #45a049;
        }
        span.copy-icon {
            cursor: pointer;
            font-size: 1.3rem;
            margin-left: 8px;
            vertical-align: middle;
            user-select: none;
            transition: color 0.3s ease;
        }
        </style>";
        echo "</head><body>";
        echo "<h2>Oluşturulan CSR ve Özel Anahtar</h2>";
        echo "<h3>Formda Girdiğiniz Bilgiler</h3>";
        echo "<pre style='font-family:poppins;font-weight: bold;'>";
        echo "Alan Adı (CN): " . htmlspecialchars($_POST['CN']) . "\n";                
        echo "Organizasyon: " . htmlspecialchars($_POST['O']) . "\n";
        echo "Organizasyon Birimi: " . htmlspecialchars($_POST['OU']) . "\n";
        echo "Şehir: " . htmlspecialchars($_POST['ST']) . "\n";
        echo "İlçe: " . htmlspecialchars($_POST['L']) . "\n";
        echo "Ülke: " . htmlspecialchars($_POST['C']) . "\n";
        echo "Anahtar Boyutu: " . htmlspecialchars($_POST['key_size']) . " bit\n";
        echo "Hash Algoritması: " . strtoupper(htmlspecialchars($hash_alg)) . "\n";
        echo "</pre>";
        echo "<h3>Özel Anahtar (Private Key) <span id='copyKeyBtn' class='copy-icon' title='Kopyala' onclick='copyKey()' style='box-shadow: 0 2px 8px rgba(0,0,0,0.2);'>📄</span></h3><pre id='keyText'>" . htmlspecialchars($pkeyout) . "</pre>";
        echo "<h3>CSR (Certificate Signing Request) <span id='copyCsrBtn' class='copy-icon' title='Kopyala' onclick='copyCSR()'style='box-shadow: 0 2px 8px rgba(0,0,0,0.2);'>📄</span></h3><pre id='csrText'>" . htmlspecialchars($csrout) . "</pre>";
        echo "<a href='" . htmlspecialchars($_SERVER['PHP_SELF']) . "' class='button'>Yeni CSR Talebi Oluştur</a>";
        echo "<script>
            function copyKey() {
                const keyContent = document.getElementById('keyText').innerText;
                const copyKeyBtn = document.getElementById('copyKeyBtn');
                navigator.clipboard.writeText(keyContent).then(() => {
                    copyKeyBtn.style.color = '#4CAF50';
                    copyKeyBtn.textContent = '✓';
                    setTimeout(() => {
                        copyKeyBtn.style.color = '';
                        copyKeyBtn.textContent = '📄';
                    }, 2000);
                }).catch(() => {
                    copyKeyBtn.style.color = 'red';
                    copyKeyBtn.textContent = '❌';
                    setTimeout(() => {
                        copyKeyBtn.style.color = '';
                        copyKeyBtn.textContent = '📄';
                    }, 2000);
                });
            }
            function copyCSR() {
                const csrContent = document.getElementById('csrText').innerText;
                const copyCsrBtn = document.getElementById('copyCsrBtn');
                navigator.clipboard.writeText(csrContent).then(() => {
                    copyCsrBtn.style.color = '#4CAF50';
                    copyCsrBtn.textContent = '✓';
                    setTimeout(() => {
                        copyCsrBtn.style.color = '';
                        copyCsrBtn.textContent = '📄';
                    }, 2000);
                }).catch(() => {
                    copyCsrBtn.style.color = 'red';
                    copyCsrBtn.textContent = '❌';
                    setTimeout(() => {
                        copyCsrBtn.style.color = '';
                        copyCsrBtn.textContent = '📄';
                    }, 2000);
                });
            }
        </script>";
        echo "</body></html>";
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8" />
    <title>CSR Oluşturucu</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
        @font-face {
            font-family: poppins;
            src: url('font/Poppins-Regular.ttf') format('truetype');
        }
        body {
            background-color: #f0f0f0;
            font-family:"poppins" ;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        form {
            background: white;
            padding: 20px 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            display: flex;
            flex-direction: column;
            max-width: 500px;
            width: 100%;
            box-sizing: border-box;
        }
        label {
            margin-top: 15px;
        }
        label:hover{
            background-color: #f0f0f0;
        }
        input {
            padding: 8px;
            max font-size: 1rem;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-top: 5px;
            box-sizing: border-box;
        }
        button {
            margin-top: 20px;
            padding: 12px;
            font-size: 1rem;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover {
            background-color: #45a049;
        }
        h2 {
            text-align: center;
            margin-bottom: 20px;
        }
        select {
    appearance: none; /* Chrome, Edge */
    -webkit-appearance: none; /* Safari */
    -moz-appearance: none; /* Firefox */
    background-color: white;
    color: #333; /* Font rengin */
    border: 1px solid #ccc;
    border-radius: 5px;
    padding: 8px;
    margin-top: 5px;
    box-sizing: border-box;
    font-family: poppins;
    cursor: pointer;
}

select:hover,
select:focus {
    background-color: #f0f0f0; /* Üzerine gelince arka plan */
    color: #333; /* Üzerine gelince font rengi */
    outline: none;
    border-color: #4CAF50; /* İsteğe bağlı hover kenar rengi */
}

option {
    background-color: white; /* Dropdown arka plan */
    color: #333; /* Dropdown yazı rengi */
}

option:hover {
    background-color: #f0f0f0; /* Dropdown hover arka plan */
    color: #333;
}

        .error-message {
            background-color: #fdecea;
            border: 1px solid #f5c2c0;
            color: #b71c1c;
            border-radius: 5px;
            padding: 10px 15px;
            margin-bottom: 15px;
            font-weight: 600;
            max-width: 500px;
            box-sizing: border-box;
        }
    </style>
</head>
<body>

<form method="post" autocomplete="off">
    <h2>CSR Oluşturmak İçin Formu Doldurunuz</h2>

    <?php if (!empty($errors)): ?>
        <div class="error-message">
            <ul style="margin:0; padding-left: 20px;">
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <label for="CN">Alan Adı</label>
    <input type="text" name="CN" id="CN" placeholder="ornek.com" required
           value="<?= htmlspecialchars($_POST['CN'] ?? '') ?>">

    <label for="O">Organizasyon</label>
    <input type="text" name="O" id="O" placeholder="TÜBİTAK" required
           value="<?= htmlspecialchars($_POST['O'] ?? '') ?>">

    <label for="OU">Organizasyon Birimi</label>
    <input type="text" name="OU" id="OU" placeholder="Ar-Ge" required
           value="<?= htmlspecialchars($_POST['OU'] ?? '') ?>">

    <label for="ST">Şehir</label>
    <input type="text" name="ST" id="ST" placeholder="Ankara" required
           value="<?= htmlspecialchars($_POST['ST'] ?? '') ?>">

    <label for="L">İlçe</label>
    <input type="text" name="L" id="L" placeholder="Çankaya" required
           value="<?= htmlspecialchars($_POST['L'] ?? '') ?>">

    <label for="C">Ülke</label>
    <input type="text" name="C" id="C" placeholder="TR" required maxlength="2"
           pattern="[A-Za-z]{2}" title="Sadece 2 harf giriniz"
           style="text-transform: uppercase;" oninput="this.value = this.value.toUpperCase()"
           value="<?= htmlspecialchars($_POST['C'] ?? '') ?>">

    <label for="key_size">Anahtar Boyutu</label>
    <select name="key_size" id="key_size" required>
        <option value="2048" <?= (($_POST['key_size'] ?? '') === '2048') ? 'selected' : '' ?>>2048 bit</option>
        <option value="4096" <?= (($_POST['key_size'] ?? '') === '4096') ? 'selected' : '' ?>>4096 bit</option>
    </select>

    <label for="hash_alg">Hash Algoritması</label>
    <select name="hash_alg" id="hash_alg" required>
        <option value="sha1" <?= (($_POST['hash_alg'] ?? '') === 'sha1') ? 'selected' : '' ?>>SHA-1</option>
        <option value="sha256" <?= (($_POST['hash_alg'] ?? '') === 'sha256') ? 'selected' : '' ?>>SHA-256</option>
        <option value="sha384" <?= (($_POST['hash_alg'] ?? '') === 'sha384') ? 'selected' : '' ?>>SHA-384</option>
        <option value="sha512" <?= (($_POST['hash_alg'] ?? '') === 'sha512') ? 'selected' : '' ?>>SHA-512</option>
    </select>

    <button type="submit">Oluştur</button>
</form>
</body>
</html>
