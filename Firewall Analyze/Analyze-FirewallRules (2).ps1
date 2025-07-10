<#
.SYNOPSIS
    (EN) Analyzes 'Allow' rules in Windows Defender Firewall and lists potentially suspicious applications.
    This version includes an automatic administrator elevation feature.
    (TR) Windows Defender Güvenlik Duvarı'ndaki 'İzin Ver' kurallarını analiz eder ve potansiyel olarak şüpheli uygulamaları listeler.
    Bu sürüm, otomatik yönetici yükseltme özelliği içerir.

.DESCRIPTION
    (EN) This script scans all rules in Windows Defender Firewall that allow inbound or outbound communication.
    It finds the application associated with each rule and checks its digital signature, file path, and publisher information.

    It specifically focuses on detecting:
    - Applications without a digital signature (may not be trustworthy).
    - Applications located in unexpected paths, such as temporary or user-specific folders.
    - Applications from unknown or suspicious publishers.

    The results are presented in a clean table format for easier review.

    (TR) Bu betik, Windows Defender Güvenlik Duvarı'ndaki gelen veya giden iletişime izin veren tüm kuralları tarar.
    Her kuralla ilişkili uygulamayı bulur ve dijital imzasını, dosya yolunu ve yayıncı bilgilerini kontrol eder.

    Özellikle şunları tespit etmeye odaklanır:
    - Dijital imzası olmayan uygulamalar (güvenilir olmayabilir).
    - Geçici veya kullanıcıya özgü klasörler gibi beklenmedik yollarda bulunan uygulamalar.
    - Bilinmeyen veya şüpheli yayıncılara ait uygulamalar.

    Sonuçlar, daha kolay incelenmesi için temiz bir tablo formatında sunulur.

.NOTES
    (EN) This script attempts to restart itself with administrator privileges if not run as an administrator.
    This is not an antivirus software. It is a helper tool to identify potential anomalies in the firewall configuration.
    (TR) Bu betik, yönetici olarak çalıştırılmazsa kendisini yönetici ayrıcalıklarıyla yeniden başlatmayı dener.
    Bu bir antivirüs yazılımı değildir. Güvenlik duvarı yapılandırmasındaki potansiyel anormallikleri belirlemeye yardımcı olan bir araçtır.

.PARAMETER ExportPath
    (EN) Specifies the file path to export the results to a CSV file.
    (TR) Sonuçları bir CSV dosyasına aktarmak için dosya yolunu belirtir.
#>
Param(
    [string]$ExportPath
)

# --- (EN) Automatic Administrator Elevation Block / (TR) Otomatik Yönetici Yükseltme Bloğu ---
# (EN) Check if the script is running as an administrator.
# (TR) Betiğin yönetici olarak çalışıp çalışmadığını kontrol et.
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # (EN) If not, display a warning and restart the script with administrator privileges.
    # (TR) Değilse, bir uyarı göster ve betiği yönetici ayrıcalıklarıyla yeniden başlat.
    Write-Warning "Administrator rights are required. Restarting the script as an administrator..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $MyInvocation.MyCommand.Path)
    exit
}
# --- (EN) End of Administrator Elevation Block / (TR) Yönetici Yükseltme Bloğunun Sonu ---


# (EN) Announce the start of the analysis.
# (TR) Analizin başladığını duyur.
Write-Host "Analyzing Windows Defender Firewall rules..." -ForegroundColor Yellow

# (EN) Get all enabled 'Allow' rules from the firewall that have an associated application.
# (TR) Güvenlik duvarından ilişkili bir uygulaması olan tüm etkin 'İzin Ver' kurallarını al.
$firewallRules = Get-NetFirewallRule -Action Allow -Enabled True | Where-Object { $_.ApplicationName }

# (EN) Initialize an array to store information about potentially suspicious applications.
# (TR) Potansiyel olarak şüpheli uygulamalar hakkındaki bilgileri saklamak için bir dizi başlat.
$suspiciousApps = @()

# (EN) Loop through each firewall rule.
# (TR) Her bir güvenlik duvarı kuralı için döngü başlat.
foreach ($rule in $firewallRules) {
    # (EN) Expand environment variables in the path (e.g., %ProgramFiles%).
    # (TR) Yoldaki ortam değişkenlerini genişlet (ör. %ProgramFiles%).
    $appPath = [System.Environment]::ExpandEnvironmentVariables($rule.ApplicationName)

    # (EN) Skip rules for generic system processes or if the application file does not exist.
    # (TR) Genel sistem süreçleri için olan veya uygulama dosyası mevcut olmayan kuralları atla.
    if ($appPath -eq "System" -or -not (Test-Path $appPath -PathType Leaf)) {
        continue
    }

    # (EN) Get the digital signature information of the application file. Suppress errors if the file is not signed.
    # (TR) Uygulama dosyasının dijital imza bilgilerini al. Dosya imzalı değilse hataları gizle.
    $signature = Get-AuthenticodeSignature -FilePath $appPath -ErrorAction SilentlyContinue

    # (EN) Get file metadata like version information.
    # (TR) Sürüm bilgisi gibi dosya meta verilerini al.
    $fileInfo = Get-Item $appPath
    $versionInfo = $fileInfo.VersionInfo

    # (EN) Initialize variables for signature details.
    # (TR) İmza detayları için değişkenleri başlat.
    $isSigned = $false
    $signer = "Unsigned"
    $status = "NotSigned"

    # (EN) If a valid signature is found, update the variables with the signer's information.
    # (TR) Geçerli bir imza bulunursa, değişkenleri imzalayanın bilgileriyle güncelle.
    if ($signature -and $signature.SignerCertificate) {
        $isSigned = $true
        $signer = $signature.SignerCertificate.SubjectName.Name
        $status = $signature.Status
    }

    # (EN) Create a list of notes to flag suspicious characteristics.
    # (TR) Şüpheli özellikleri işaretlemek için bir not listesi oluştur.
    $notes = @()
    if (-not $isSigned) {
        $notes += "Application is unsigned."
    }
    if ($appPath -like "*\AppData\*") {
        $notes += "Located in AppData folder."
    }
    if ($appPath -like "*\Temp\*") {
        $notes += "Located in a temporary folder."
    }
    if ($signer -notlike "CN=Microsoft*") {
        $notes += "Non-Microsoft publisher."
    }


    # (EN) Create a custom PowerShell object to hold all the collected information for this application.
    # (TR) Bu uygulama için toplanan tüm bilgileri tutacak özel bir PowerShell nesnesi oluştur.
    $appObject = [PSCustomObject]@{
        ApplicationName = $versionInfo.FileDescription -or (Split-Path $appPath -Leaf)
        Path            = $appPath
        IsSigned        = $isSigned
        Signer          = $signer
        Status          = $status
        Notes           = $notes -join " "
        RuleName        = $rule.DisplayName
    }

    # (EN) Add the application object to our list of suspicious apps.
    # (TR) Uygulama nesnesini şüpheli uygulamalar listemize ekle.
    $suspiciousApps += $appObject
}

# (EN) Check if any applications were flagged.
# (TR) Herhangi bir uygulamanın işaretlenip işaretlenmediğini kontrol et.
if ($suspiciousApps.Count -eq 0) {
    # (EN) If no applications were found, print a success message.
    # (TR) Hiçbir uygulama bulunamadıysa, bir başarı mesajı yazdır.
    Write-Host "Analysis complete. No 'Allow' rules were found to analyze, or the applications associated with the rules could not be accessed." -ForegroundColor Green
}
else {
    # (EN) If applications were found, print a header for the results.
    # (TR) Uygulamalar bulunduysa, sonuçlar için bir başlık yazdır.
    Write-Host "Analysis complete. Applications associated with 'Allow' rules are listed below:" -ForegroundColor Cyan
    
    # (EN) Display the results in a table. Sort by the length of the 'Notes' field to bring more suspicious items to the top.
    # (TR) Sonuçları bir tabloda göster. Daha şüpheli öğeleri üste taşımak için 'Notlar' alanının uzunluğuna göre sırala.
    $sortedApps = $suspiciousApps | Sort-Object { $_.Notes.Length } -Descending
    $sortedApps | Format-Table -AutoSize -Wrap -Property ApplicationName, IsSigned, Signer, Path, Notes, RuleName

    # (EN) If an export path is provided, save the results to a CSV file.
    # (TR) Eğer bir dışa aktarma yolu belirtilmişse, sonuçları bir CSV dosyasına kaydet.
    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        try {
            $sortedApps | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "Results have been exported to $ExportPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export results to $ExportPath. Error: $_"
        }
    }
}

# (EN) Prompt the user to press a key before exiting, to keep the window open.
# (TR) Pencereyi açık tutmak için çıkmadan önce kullanıcıdan bir tuşa basmasını iste.
Write-Host "`nScript finished. Press any key to exit..." -ForegroundColor Green
Read-Host
