# Forcepoint DLP - Endpoint Status Temizliği

`ForcepointAgentCleanup.ps1`, Forcepoint Security Manager (FSM) konsolundaki **Status > Endpoint Status** listesinde uzun süredir bağlanmayan agent kayıtlarını listeler ve çift onayla siler.

## Ne yapar?

1. SQL Server'a bağlanır (`sqlcmd.exe`, Windows veya SQL Server kimlik doğrulama).
2. Sistemdeki toplam agent sayısını verir.
3. **7 / 15 / 30 gündür** erişmeyen agentları sayar ve Hostname, IP, Last Update, Sync, kullanıcı ve versiyon bilgileriyle listeler.
4. Kaç günden eski kayıtların silineceğini sorar.
5. **Çift onay** ister: önce E/H, ardından silinecek kayıt sayısının elle yazılması.
6. Silinecek kayıtları masaüstüne CSV olarak yedekler, tek bir transaction içinde siler ve silinen agent sayısını raporlar.

"Erişmeyen" süresi, `PA_DYNAMIC_STATUS.UPDATE_DATE` alanından hesaplanır (FSM konsolundaki **Last Update**).

## Kapsam ve güvenlik

- Yalnızca iki tablodan, **yalnızca ekranda gösterilip onaylanan agentların** satırları silinir:
  - `PA_DYNAMIC_STATUS_PROPS` (agent durum özellikleri)
  - `PA_DYNAMIC_STATUS` (Endpoint Status satırı)
- Incident, politika, kullanıcı veya başka bir tabloya dokunulmaz. `DROP`, `TRUNCATE`, `UPDATE` veya `ALTER` kullanılmaz.
- Onaylardan biri verilmezse hiçbir şey silinmez.
- Listeleme ile silme arasında yeniden bağlanan agentlar silinmez.
- Last Update bilgisi boş olan kayıtlar silme kapsamına alınmaz.
- Hata olursa transaction geri alınır.
- Bu işlem makinelerdeki agentı **kaldırmaz**. Agent tekrar bağlanırsa kaydı yeniden oluşur.

## Kullanım

```powershell
.\ForcepointAgentCleanup.ps1
```

```powershell
.\ForcepointAgentCleanup.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa
```

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `-SqlServerInstance` | (sorulur) | SQL Server adı, örn. `SUNUCU` veya `SUNUCU\INSTANCE` |
| `-SqlDatabaseName` | `wbsn-data-security` | Forcepoint DLP veritabanı |
| `-SqlAuthMode` | (sorulur) | `Windows` veya `SqlLogin` |
| `-SqlUserName` | (sorulur) | SQL Login kullanıcı adı; parola güvenli olarak sorulur |

Gereksinimler: Windows PowerShell 5.1+, PATH'te `sqlcmd.exe`, veritabanında ilgili tablolar için okuma/silme yetkisi.

## Ekran görüntüleri

> Görüntüler, örnek agent verisiyle yapılan test çalıştırmasından alınmıştır. Hostname, IP ve kullanıcı adları gerçek değildir.

### 1. Bağlantı, özet ve eski agent listeleri

![Bağlantı, özet ve liste](docs/images/01-baglanti-ozet-liste.png)

### 2. Gün seçimi, çift onay ve silme sonucu

![Seçim, çift onay ve silme](docs/images/02-secim-cift-onay-silme.png)

### 3. İkinci onay eşleşmezse işlem iptal edilir

![İkinci onay iptal](docs/images/03-ikinci-onay-iptal.png)

### 4. Birinci onayda "H" verilirse işlem iptal edilir

![Birinci onay iptal](docs/images/04-birinci-onay-iptal.png)

### 5. Eski agent yoksa silme sorusu sorulmaz

![Eski agent yok](docs/images/05-eski-agent-yok.png)

---

Hazırlayan: FIRAT AYDIN / Barikat Siber Güvenlik
