<#
.SYNOPSIS
    Windows Defender Güvenlik Duvarı'ndaki "İzin Ver" kurallarını analiz eder ve potansiyel olarak şüpheli uygulamaları listeler.

.DESCRIPTION
    Bu betik, Windows Defender Güvenlik Duvarı'nda tanımlı olan ve dışarıdan veya içeriye doğru iletişime izin veren tüm kuralları tarar.
    Her kuralın ilişkili olduğu uygulamayı bulur ve bu uygulamanın dijital imzasını, dosya yolunu ve yayıncı bilgilerini kontrol eder.

    Özellikle aşağıdaki durumları tespit etmeye odaklanır:
    - Dijital imzası olmayan uygulamalar (güvenilir olmayabilir).
    - Geçici veya kullanıcıya özel klasörler gibi beklenmedik konumlarda bulunan uygulamalar.
    - Bilinmeyen veya şüpheli yayıncılara ait uygulamalar.

    Sonuçları, daha kolay incelenebilmesi için düzenli bir tablo formatında sunar.

.OUTPUTS
    System.Object - İncelenen her uygulama için ayrıntılı bilgi içeren bir nesne dizisi.

.NOTES
    Bu betik, yönetici hakları ile çalıştırılmalıdır, aksi takdirde tüm güvenlik duvarı kurallarına erişemeyebilir.
    Bu bir antivirüs yazılımı değildir. Yalnızca güvenlik duvarı yapılandırmasındaki potansiyel anormallikleri tespit etmek için bir yardımcı araçtır.
#>

# Betiğin yönetici olarak çalıştırıldığından emin ol
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Bu betik, tüm güvenlik duvarı kurallarına erişmek için Yönetici olarak çalıştırılmalıdır."
    Write-Warning "Lütfen PowerShell'i Yönetici olarak başlatın ve betiği tekrar çalıştırın."
    exit
}

Write-Host "Windows Defender Güvenlik Duvarı kuralları analiz ediliyor..." -ForegroundColor Yellow

# Güvenlik duvarındaki "İzin Ver" kurallarını al
$firewallRules = Get-NetFirewallRule -Action Allow -Enabled True | Where-Object { $_.ApplicationName }

$suspiciousApps = @()

foreach ($rule in $firewallRules) {
    # Ortam değişkenlerini gerçek yollara çevir
    $appPath = [System.Environment]::ExpandEnvironmentVariables($rule.ApplicationName)

    # Uygulama yolu "System" gibi genel bir ifade ise atla
    if ($appPath -eq "System" -or -not (Test-Path $appPath -PathType Leaf)) {
        continue
    }

    # Uygulamanın imza bilgilerini al
    $signature = Get-AuthenticodeSignature -FilePath $appPath -ErrorAction SilentlyContinue

    $fileInfo = Get-Item $appPath
    $versionInfo = $fileInfo.VersionInfo

    $isSigned = $false
    $signer = "İmzasız"
    $status = "NotSigned"

    if ($signature -and $signature.SignerCertificate) {
        $isSigned = $true
        $signer = $signature.SignerCertificate.SubjectName.Name
        $status = $signature.Status
    }

    # Şüpheli durumları kontrol etmek için bir not alanı
    $notes = @()
    if (-not $isSigned) {
        $notes += "Uygulama imzasız."
    }
    if ($appPath -like "*\AppData\*") {
        $notes += "AppData klasöründe bulunuyor."
    }
    if ($appPath -like "*\Temp\*") {
        $notes += "Geçici bir klasörde bulunuyor."
    }
    if ($signer -notlike "CN=Microsoft*") {
        $notes += "Microsoft dışı bir yayıncı."
    }


    $appObject = [PSCustomObject]@{
        ApplicationName = $versionInfo.FileDescription -or (Split-Path $appPath -Leaf)
        Path            = $appPath
        IsSigned        = $isSigned
        Signer          = $signer
        Status          = $status
        Notes           = $notes -join " "
        RuleName        = $rule.DisplayName
    }

    $suspiciousApps += $appObject
}

if ($suspiciousApps.Count -eq 0) {
    Write-Host "Analiz tamamlandı. Şüpheli bir kural veya uygulama bulunamadı." -ForegroundColor Green
}
else {
    Write-Host "Analiz tamamlandı. Aşağıda potansiyel olarak şüpheli uygulamaların listesi bulunmaktadır:" -ForegroundColor Cyan
    
    # Sonuçları ekrana yazdır, Notlar sütununa göre renklendir
    $suspiciousApps | ForEach-Object {
        if ($_.Notes) {
            # Şüpheli notlar varsa Kırmızı renkte yazdır
            Write-Host "--------------------------------------------------"
            Write-Host "Uygulama Adı : " -NoNewline; Write-Host $_.ApplicationName -ForegroundColor White
            Write-Host "Yol           : " -NoNewline; Write-Host $_.Path -ForegroundColor White
            Write-Host "İmzalı Mı?    : " -NoNewline; Write-Host $_.IsSigned -ForegroundColor $(if ($_.IsSigned) { 'Green' } else { 'Red' })
            Write-Host "Yayıncı       : " -NoNewline; Write-Host $_.Signer -ForegroundColor White
            Write-Host "Durum         : " -NoNewline; Write-Host $_.Status -ForegroundColor White
            Write-Host "Kural Adı     : " -NoNewline; Write-Host $_.RuleName -ForegroundColor White
            Write-Host "Notlar        : " -NoNewline; Write-Host $_.Notes -ForegroundColor Red
        }
    }
    
    # Ayrıca, tüm listeyi daha detaylı inceleme için bir tablo olarak göster
    Write-Host "`nTüm 'İzin Ver' Kurallarına Ait Uygulamaların Tam Listesi:" -ForegroundColor Yellow
    $suspiciousApps | Format-Table -AutoSize -Wrap
}

Write-Host "`nBetik tamamlandı." -ForegroundColor Green