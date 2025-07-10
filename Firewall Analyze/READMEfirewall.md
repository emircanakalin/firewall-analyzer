# Firewall Analyzer

## Description

This PowerShell script analyzes the "Allow" rules in Windows Defender Firewall to identify and list potentially suspicious applications. It is designed to help system administrators and security-conscious users detect unauthorized or untrustworthy applications that have been granted network access.

### Key Features:
- **Automatic Administrator Elevation**: The script automatically requests administrator privileges if not already running with them.
- **Signature Verification**: Checks if an application is digitally signed and displays the publisher's information.
- **Path Analysis**: Identifies applications running from unusual locations, such as temporary (`Temp`) or user-specific (`AppData`) folders.
- **Publisher Filtering**: Flags applications from non-Microsoft publishers for closer inspection.
- **Clear Reporting**: Presents the findings in a clean, easy-to-read table, sorted to highlight the most suspicious entries.
- **CSV Export**: Allows exporting the analysis results to a CSV file for further analysis.

---

## Açıklama

Bu PowerShell betiği, potansiyel olarak şüpheli uygulamaları belirlemek ve listelemek için Windows Defender Güvenlik Duvarı'ndaki "İzin Ver" kurallarını analiz eder. Sistem yöneticilerinin ve güvenliğe duyarlı kullanıcıların, ağ erişimi verilmiş yetkisiz veya güvenilir olmayan uygulamaları tespit etmelerine yardımcı olmak için tasarlanmıştır.

### Öne Çıkan Özellikler:
- **Otomatik Yönetici Yükseltme**: Betik, yönetici olarak çalışmıyorsa otomatik olarak yönetici ayrıcalıkları ister.
- **İmza Doğrulaması**: Bir uygulamanın dijital olarak imzalanıp imzalanmadığını kontrol eder ve yayıncı bilgilerini gösterir.
- **Yol Analizi**: Geçici (`Temp`) veya kullanıcıya özgü (`AppData`) klasörler gibi olağandışı konumlardan çalışan uygulamaları tanımlar.
- **Yayıncı Filtreleme**: Microsoft dışındaki yayıncılara ait uygulamaları daha yakından incelenmesi için işaretler.
- **Anlaşılır Raporlama**: Bulguları, en şüpheli girişleri vurgulayacak şekilde sıralanmış, temiz ve okunması kolay bir tabloda sunar.
- **CSV Dışa Aktarma**: Analiz sonuçlarını daha fazla analiz için bir CSV dosyasına aktarmaya olanak tanır.

## Usage / Kullanım

1.  Save the script as a `.ps1` file (e.g., `Firewall-Analyzer.ps1`).
2.  Open PowerShell.
3.  Navigate to the directory where you saved the script.
4.  Run the script with the following command:
    ```powershell
    .\Firewall-Analyzer.ps1
    ```
The script will automatically request administrator rights and display the analysis results in the console.

To export the results to a CSV file, use the `-ExportPath` parameter:
```powershell
.\Firewall-Analyzer.ps1 -ExportPath "C:\path\to\your\results.csv"
```

1.  Betiği bir `.ps1` dosyası olarak kaydedin (ör. `Firewall-Analyzer.ps1`).
2.  PowerShell'i açın.
3.  Betiği kaydettiğiniz dizine gidin.
4.  Betiği aşağıdaki komutla çalıştırın:
    ```powershell
    .\Firewall-Analyzer.ps1
    ```
Betik, otomatik olarak yönetici hakları isteyecek ve analiz sonuçlarını konsolda gösterecektir.

Sonuçları bir CSV dosyasına aktarmak için `-ExportPath` parametresini kullanın:
```powershell
.\Firewall-Analyzer.ps1 -ExportPath "C:\path\to\your\results.csv"
```
