# 01 — Mimari: Komutlar Nasıl Bağlanıyor

winspect tek bir `.exe`, ama içinde birçok alt-komut var (`pe`, `inspect`,
`token`...). Bu dosya, `winspect pe notepad.exe` yazdığında doğru kodun nasıl
çalıştırıldığını anlatıyor. Dosya: `src/main.c`.

---

## 1. Dosya düzeni

```
winspect/
├── inc/            başlık dosyaları (.h): her komutun prototipi
│   ├── pe.h
│   ├── inspect.h
│   └── ...
├── src/            kaynak dosyalar (.c): asıl kod
│   ├── main.c      komutları dağıtan "santral"
│   ├── pe.c
│   ├── inspect.c
│   └── ...
├── CMakeLists.txt  nasıl derleneceği
└── docs/           bu dokümanlar
```

Her komut **kendi dosyasında** yaşar. `pe` komutu `src/pe.c`'de, prototipi
`inc/pe.h`'de. `main.c` sadece `pe.h`'yi include eder ve `cmd_pe` fonksiyonunu
çağırır. `main.c` komutun *nasıl* çalıştığını bilmez; sadece onu çağırmayı bilir.

Bu ayrımın faydası: yeni bir komut eklemek için `main.c`'yi neredeyse hiç
değiştirmezsin. Yeni bir `.c` dosyası yazar, tabloya bir satır eklersin. Buna
**Open/Closed ilkesi** denir: eklemeye açık, değiştirmeye kapalı.

---

## 2. Ortak imza: her komut aynı şekle sahip

`main.c`'nin tepesinde şu tanım var:

```c
typedef int (*cmd_fn)(int argc, char** argv);
```

Bu, "bir komut fonksiyonu şöyle görünür" demek: `int` döndürür, `argc` (argüman
sayısı) ve `argv` (argüman dizisi) alır. **Bütün** komutlar bu imzaya uyar:
`cmd_pe`, `cmd_inspect`, hepsi. Aynı şekle sahip oldukları için hepsini tek bir
tabloya koyabiliriz.

Dönüş değeri = programın çıkış kodu. `0` = başarı, başka her şey = hata. Bu önemli:
CI (otomatik test) bu koda bakar. Komut `0` dışında bir şey döndürürse GitHub
Actions adımı **kırmızı** yanar. Yani çıkış kodu doğru olmalı.

---

## 3. Komut tablosu: isimden fonksiyona eşleme

`main.c`'nin kalbi bu tablo:

```c
static const struct {
    const char* name;   // kullanıcının yazdığı kelime: "pe"
    cmd_fn      fn;      // o kelimeye karşılık gelen fonksiyon: cmd_pe
    const char* help;   // yardım ekranında görünen açıklama
} commands[] = {
    { "list",    cmd_list,    "process/thread tree via Toolhelp" },
    { "pe",      cmd_pe,      "parse and dump PE file headers"   },
    { "inspect", cmd_inspect, "dump a live process PEB ..."      },
    ...
};
```

Bu bir **veri tablosu**. Her satır bir komut. Kodun mantığı değil, verisi
değişerek büyüyor. Yeni komut = yeni satır.

Bu fikir — "davranışı if/else yerine bir tabloyla sürmek" — winspect'te sürekli
tekrar eder. PE flag'lerini basarken de (`pe.c`'deki `flag_name` tablosu), access
maskesini çözerken de aynı desen. Bir kez anladığında her yerde görürsün.

---

## 4. Dağıtım (dispatch): doğru komutu bulmak

`main` fonksiyonu kabaca şunu yapar:

```c
int main(int argc, char** argv) {
    if (argc < 2) {          // hiç alt-komut yazılmamış
        usage();             // yardım göster
        return 1;
    }
    // Tabloyu baştan sona tara, argv[1] ile eşleşen ismi bul
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(argv[1], commands[i].name) == 0) {
            return commands[i].fn(argc - 2, argv + 2);   // bulundu, çağır
        }
    }
    // Döngü bitti, eşleşme yok
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    usage();
    return 1;
}
```

İki ince nokta var:

### `strcmp` ile doğrusal tarama, neden?

Bu bölüm yazıldığında ~10 komut vardı; bugün 59 var ve gerekçe hâlâ geçerli.
"Daha hızlı" diye hash tablosu ya da ikili arama kurmak burada mantıksız: 59
elemanlık bir listede `strcmp` döngüsü zaten anında biter ve çok daha basittir. Bu arama program başına **bir kez** çalışır, hız kritik değil.
Basitlik > erken optimizasyon.

### `argc - 2, argv + 2`: argüman kaydırma

Kullanıcı şunu yazdı: `winspect pe notepad.exe`

Program açısından:
```
argv[0] = "winspect"      (program yolu)
argv[1] = "pe"            (alt-komut)
argv[2] = "notepad.exe"   (pe'nin asıl argümanı)
argc    = 3
```

`cmd_pe`'yi çağırırken `argv + 2` veriyoruz, yani diziyi **2 ileri** kaydırıyoruz.
`cmd_pe` açısından:
```
argv[0] = "notepad.exe"   (artık ilk argüman bu)
argc    = 1
```

Böylece `cmd_pe`, kendisinin bir alt-komut olduğunu bile bilmez. Sanki kendi
başına çalışan bir programmış gibi, kendi argümanlarını `argv[0]`'dan itibaren
görür. Bu kopyalama/ayırma yapmadan, sadece pointer aritmetiğiyle olur — hiçbir
şey kopyalanmaz, sadece "nereden başlayacağın" değişir.

---

## 5. Özet

- Her komut kendi `.c`/`.h` ikilisinde, ortak `cmd_fn` imzasına uyar.
- `main.c` bir **tablo** tutar (isim → fonksiyon) ve `argv[1]`'e göre doğru
  fonksiyonu çağırır.
- Argümanları 2 kaydırıp verir, böylece her komut bağımsız bir araç gibi davranır.
- Yeni komut eklemek: yeni dosya + tabloya bir satır. `main`'in mantığı değişmez.

Sıradaki: [02 — pe](02-pe.md), ilk ve en çok öğreten komut.
