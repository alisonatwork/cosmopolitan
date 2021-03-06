#ifndef COSMOPOLITAN_LIBC_NT_ENUM_LANG_H_
#define COSMOPOLITAN_LIBC_NT_ENUM_LANG_H_

#define MAKELANGID(p, s) ((((uint16_t)(s)) << 10) | (uint16_t)(p))

#define kNtLangNeutral            0x00
#define kNtLangInvariant          0x7f
#define kNtLangAfrikaans          0x36
#define kNtLangAlbanian           0x1c
#define kNtLangAlsatian           0x84
#define kNtLangAmharic            0x5e
#define kNtLangArabic             0x01
#define kNtLangArmenian           0x2b
#define kNtLangAssamese           0x4d
#define kNtLangAzeri              0x2c
#define kNtLangAzerbaijani        0x2c
#define kNtLangBangla             0x45
#define kNtLangBashkir            0x6d
#define kNtLangBasque             0x2d
#define kNtLangBelarusian         0x23
#define kNtLangBengali            0x45
#define kNtLangBreton             0x7e
#define kNtLangBosnian            0x1a
#define kNtLangBosnianNeutral     0x781a
#define kNtLangBulgarian          0x02
#define kNtLangCatalan            0x03
#define kNtLangCentralKurdish     0x92
#define kNtLangCherokee           0x5c
#define kNtLangChinese            0x04
#define kNtLangChineseSimplified  0x04
#define kNtLangChineseTraditional 0x7c04
#define kNtLangCorsican           0x83
#define kNtLangCroatian           0x1a
#define kNtLangCzech              0x05
#define kNtLangDanish             0x06
#define kNtLangDari               0x8c
#define kNtLangDivehi             0x65
#define kNtLangDutch              0x13
#define kNtLangEnglish            0x09
#define kNtLangEstonian           0x25
#define kNtLangFaeroese           0x38
#define kNtLangFarsi              0x29
#define kNtLangFilipino           0x64
#define kNtLangFinnish            0x0b
#define kNtLangFrench             0x0c
#define kNtLangFrisian            0x62
#define kNtLangFulah              0x67
#define kNtLangGalician           0x56
#define kNtLangGeorgian           0x37
#define kNtLangGerman             0x07
#define kNtLangGreek              0x08
#define kNtLangGreenlandic        0x6f
#define kNtLangGujarati           0x47
#define kNtLangHausa              0x68
#define kNtLangHawaiian           0x75
#define kNtLangHebrew             0x0d
#define kNtLangHindi              0x39
#define kNtLangHungarian          0x0e
#define kNtLangIcelandic          0x0f
#define kNtLangIgbo               0x70
#define kNtLangIndonesian         0x21
#define kNtLangInuktitut          0x5d
#define kNtLangIrish              0x3c
#define kNtLangItalian            0x10
#define kNtLangJapanese           0x11
#define kNtLangKannada            0x4b
#define kNtLangKashmiri           0x60
#define kNtLangKazak              0x3f
#define kNtLangKhmer              0x53
#define kNtLangKiche              0x86
#define kNtLangKinyarwanda        0x87
#define kNtLangKonkani            0x57
#define kNtLangKorean             0x12
#define kNtLangKyrgyz             0x40
#define kNtLangLao                0x54
#define kNtLangLatvian            0x26
#define kNtLangLithuanian         0x27
#define kNtLangLowerSorbian       0x2e
#define kNtLangLuxembourgish      0x6e
#define kNtLangMacedonian         0x2f
#define kNtLangMalay              0x3e
#define kNtLangMalayalam          0x4c
#define kNtLangMaltese            0x3a
#define kNtLangManipuri           0x58
#define kNtLangMaori              0x81
#define kNtLangMapudungun         0x7a
#define kNtLangMarathi            0x4e
#define kNtLangMohawk             0x7c
#define kNtLangMongolian          0x50
#define kNtLangNepali             0x61
#define kNtLangNorwegian          0x14
#define kNtLangOccitan            0x82
#define kNtLangOdia               0x48
#define kNtLangOriya              0x48
#define kNtLangPashto             0x63
#define kNtLangPersian            0x29
#define kNtLangPolish             0x15
#define kNtLangPortuguese         0x16
#define kNtLangPular              0x67
#define kNtLangPunjabi            0x46
#define kNtLangQuechua            0x6b
#define kNtLangRomanian           0x18
#define kNtLangRomansh            0x17
#define kNtLangRussian            0x19
#define kNtLangSakha              0x85
#define kNtLangSami               0x3b
#define kNtLangSanskrit           0x4f
#define kNtLangScottishGaelic     0x91
#define kNtLangSerbian            0x1a
#define kNtLangSerbianNeutral     0x7c1a
#define kNtLangSindhi             0x59
#define kNtLangSinhalese          0x5b
#define kNtLangSlovak             0x1b
#define kNtLangSlovenian          0x24
#define kNtLangSotho              0x6c
#define kNtLangSpanish            0x0a
#define kNtLangSwahili            0x41
#define kNtLangSwedish            0x1d
#define kNtLangSyriac             0x5a
#define kNtLangTajik              0x28
#define kNtLangTamazight          0x5f
#define kNtLangTamil              0x49
#define kNtLangTatar              0x44
#define kNtLangTelugu             0x4a
#define kNtLangThai               0x1e
#define kNtLangTibetan            0x51
#define kNtLangTigrigna           0x73
#define kNtLangTigrinya           0x73
#define kNtLangTswana             0x32
#define kNtLangTurkish            0x1f
#define kNtLangTurkmen            0x42
#define kNtLangUighur             0x80
#define kNtLangUkrainian          0x22
#define kNtLangUpperSorbian       0x2e
#define kNtLangUrdu               0x20
#define kNtLangUzbek              0x43
#define kNtLangValencian          0x03
#define kNtLangVietnamese         0x2a
#define kNtLangWelsh              0x52
#define kNtLangWolof              0x88
#define kNtLangXhosa              0x34
#define kNtLangYakut              0x85
#define kNtLangYi                 0x78
#define kNtLangYoruba             0x6a
#define kNtLangZulu               0x35

#define kNtSublangNeutral                          0x00
#define kNtSublangDefault                          0x01
#define kNtSublangSysDefault                       0x02
#define kNtSublangCustomDefault                    0x03
#define kNtSublangCustomUnspecified                0x04
#define kNtSublangUiCustomDefault                  0x05
#define kNtSublangAfrikaansSouthAfrica             0x01
#define kNtSublangAlbanianAlbania                  0x01
#define kNtSublangAlsatianFrance                   0x01
#define kNtSublangAmharicEthiopia                  0x01
#define kNtSublangArabicSaudiArabia                0x01
#define kNtSublangArabicIraq                       0x02
#define kNtSublangArabicEgypt                      0x03
#define kNtSublangArabicLibya                      0x04
#define kNtSublangArabicAlgeria                    0x05
#define kNtSublangArabicMorocco                    0x06
#define kNtSublangArabicTunisia                    0x07
#define kNtSublangArabicOman                       0x08
#define kNtSublangArabicYemen                      0x09
#define kNtSublangArabicSyria                      0x0a
#define kNtSublangArabicJordan                     0x0b
#define kNtSublangArabicLebanon                    0x0c
#define kNtSublangArabicKuwait                     0x0d
#define kNtSublangArabicUae                        0x0e
#define kNtSublangArabicBahrain                    0x0f
#define kNtSublangArabicQatar                      0x10
#define kNtSublangArmenianArmenia                  0x01
#define kNtSublangAssameseIndia                    0x01
#define kNtSublangAzeriLatin                       0x01
#define kNtSublangAzeriCyrillic                    0x02
#define kNtSublangAzerbaijaniAzerbaijanLatin       0x01
#define kNtSublangAzerbaijaniAzerbaijanCyrillic    0x02
#define kNtSublangBanglaIndia                      0x01
#define kNtSublangBanglaBangladesh                 0x02
#define kNtSublangBashkirRussia                    0x01
#define kNtSublangBasqueBasque                     0x01
#define kNtSublangBelarusianBelarus                0x01
#define kNtSublangBengaliIndia                     0x01
#define kNtSublangBengaliBangladesh                0x02
#define kNtSublangBosnianBosniaHerzegovinaLatin    0x05
#define kNtSublangBosnianBosniaHerzegovinaCyrillic 0x08
#define kNtSublangBretonFrance                     0x01
#define kNtSublangBulgarianBulgaria                0x01
#define kNtSublangCatalanCatalan                   0x01
#define kNtSublangCentralKurdishIraq               0x01
#define kNtSublangCherokeeCherokee                 0x01
#define kNtSublangChineseTraditional               0x01
#define kNtSublangChineseSimplified                0x02
#define kNtSublangChineseHongkong                  0x03
#define kNtSublangChineseSingapore                 0x04
#define kNtSublangChineseMacau                     0x05
#define kNtSublangCorsicanFrance                   0x01
#define kNtSublangCzechCzechRepublic               0x01
#define kNtSublangCroatianCroatia                  0x01
#define kNtSublangCroatianBosniaHerzegovinaLatin   0x04
#define kNtSublangDanishDenmark                    0x01
#define kNtSublangDariAfghanistan                  0x01
#define kNtSublangDivehiMaldives                   0x01
#define kNtSublangDutch                            0x01
#define kNtSublangDutchBelgian                     0x02
#define kNtSublangEnglishUs                        0x01
#define kNtSublangEnglishUk                        0x02
#define kNtSublangEnglishAus                       0x03
#define kNtSublangEnglishCan                       0x04
#define kNtSublangEnglishNz                        0x05
#define kNtSublangEnglishEire                      0x06
#define kNtSublangEnglishSouthAfrica               0x07
#define kNtSublangEnglishJamaica                   0x08
#define kNtSublangEnglishCaribbean                 0x09
#define kNtSublangEnglishBelize                    0x0a
#define kNtSublangEnglishTrinidad                  0x0b
#define kNtSublangEnglishZimbabwe                  0x0c
#define kNtSublangEnglishPhilippines               0x0d
#define kNtSublangEnglishIndia                     0x10
#define kNtSublangEnglishMalaysia                  0x11
#define kNtSublangEnglishSingapore                 0x12
#define kNtSublangEstonianEstonia                  0x01
#define kNtSublangFaeroeseFaroeIslands             0x01
#define kNtSublangFilipinoPhilippines              0x01
#define kNtSublangFinnishFinland                   0x01
#define kNtSublangFrench                           0x01
#define kNtSublangFrenchBelgian                    0x02
#define kNtSublangFrenchCanadian                   0x03
#define kNtSublangFrenchSwiss                      0x04
#define kNtSublangFrenchLuxembourg                 0x05
#define kNtSublangFrenchMonaco                     0x06
#define kNtSublangFrisianNetherlands               0x01
#define kNtSublangFulahSenegal                     0x02
#define kNtSublangGalicianGalician                 0x01
#define kNtSublangGeorgianGeorgia                  0x01
#define kNtSublangGerman                           0x01
#define kNtSublangGermanSwiss                      0x02
#define kNtSublangGermanAustrian                   0x03
#define kNtSublangGermanLuxembourg                 0x04
#define kNtSublangGermanLiechtenstein              0x05
#define kNtSublangGreekGreece                      0x01
#define kNtSublangGreenlandicGreenland             0x01
#define kNtSublangGujaratiIndia                    0x01
#define kNtSublangHausaNigeriaLatin                0x01
#define kNtSublangHawaiianUs                       0x01
#define kNtSublangHebrewIsrael                     0x01
#define kNtSublangHindiIndia                       0x01
#define kNtSublangHungarianHungary                 0x01
#define kNtSublangIcelandicIceland                 0x01
#define kNtSublangIgboNigeria                      0x01
#define kNtSublangIndonesianIndonesia              0x01
#define kNtSublangInuktitutCanada                  0x01
#define kNtSublangInuktitutCanadaLatin             0x02
#define kNtSublangIrishIreland                     0x02
#define kNtSublangItalian                          0x01
#define kNtSublangItalianSwiss                     0x02
#define kNtSublangJapaneseJapan                    0x01
#define kNtSublangKannadaIndia                     0x01
#define kNtSublangKashmiriSasia                    0x02
#define kNtSublangKashmiriIndia                    0x02
#define kNtSublangKazakKazakhstan                  0x01
#define kNtSublangKhmerCambodia                    0x01
#define kNtSublangKicheGuatemala                   0x01
#define kNtSublangKinyarwandaRwanda                0x01
#define kNtSublangKonkaniIndia                     0x01
#define kNtSublangKorean                           0x01
#define kNtSublangKyrgyzKyrgyzstan                 0x01
#define kNtSublangLaoLao                           0x01
#define kNtSublangLatvianLatvia                    0x01
#define kNtSublangLithuanian                       0x01
#define kNtSublangLowerSorbianGermany              0x02
#define kNtSublangLuxembourgishLuxembourg          0x01
#define kNtSublangMacedonianMacedonia              0x01
#define kNtSublangMalayMalaysia                    0x01
#define kNtSublangMalayBruneiDarussalam            0x02
#define kNtSublangMalayalamIndia                   0x01
#define kNtSublangMalteseMalta                     0x01
#define kNtSublangMaoriNewZealand                  0x01
#define kNtSublangMapudungunChile                  0x01
#define kNtSublangMarathiIndia                     0x01
#define kNtSublangMohawkMohawk                     0x01
#define kNtSublangMongolianCyrillicMongolia        0x01
#define kNtSublangMongolianPrc                     0x02
#define kNtSublangNepaliIndia                      0x02
#define kNtSublangNepaliNepal                      0x01
#define kNtSublangNorwegianBokmal                  0x01
#define kNtSublangNorwegianNynorsk                 0x02
#define kNtSublangOccitanFrance                    0x01
#define kNtSublangOdiaIndia                        0x01
#define kNtSublangOriyaIndia                       0x01
#define kNtSublangPashtoAfghanistan                0x01
#define kNtSublangPersianIran                      0x01
#define kNtSublangPolishPoland                     0x01
#define kNtSublangPortuguese                       0x02
#define kNtSublangPortugueseBrazilian              0x01
#define kNtSublangPularSenegal                     0x02
#define kNtSublangPunjabiIndia                     0x01
#define kNtSublangPunjabiPakistan                  0x02
#define kNtSublangQuechuaBolivia                   0x01
#define kNtSublangQuechuaEcuador                   0x02
#define kNtSublangQuechuaPeru                      0x03
#define kNtSublangRomanianRomania                  0x01
#define kNtSublangRomanshSwitzerland               0x01
#define kNtSublangRussianRussia                    0x01
#define kNtSublangSakhaRussia                      0x01
#define kNtSublangSamiNorthernNorway               0x01
#define kNtSublangSamiNorthernSweden               0x02
#define kNtSublangSamiNorthernFinland              0x03
#define kNtSublangSamiLuleNorway                   0x04
#define kNtSublangSamiLuleSweden                   0x05
#define kNtSublangSamiSouthernNorway               0x06
#define kNtSublangSamiSouthernSweden               0x07
#define kNtSublangSamiSkoltFinland                 0x08
#define kNtSublangSamiInariFinland                 0x09
#define kNtSublangSanskritIndia                    0x01
#define kNtSublangScottishGaelic                   0x01
#define kNtSublangSerbianBosniaHerzegovinaLatin    0x06
#define kNtSublangSerbianBosniaHerzegovinaCyrillic 0x07
#define kNtSublangSerbianMontenegroLatin           0x0b
#define kNtSublangSerbianMontenegroCyrillic        0x0c
#define kNtSublangSerbianSerbiaLatin               0x09
#define kNtSublangSerbianSerbiaCyrillic            0x0a
#define kNtSublangSerbianCroatia                   0x01
#define kNtSublangSerbianLatin                     0x02
#define kNtSublangSerbianCyrillic                  0x03
#define kNtSublangSindhiIndia                      0x01
#define kNtSublangSindhiPakistan                   0x02
#define kNtSublangSindhiAfghanistan                0x02
#define kNtSublangSinhaleseSriLanka                0x01
#define kNtSublangSothoNorthernSouthAfrica         0x01
#define kNtSublangSlovakSlovakia                   0x01
#define kNtSublangSlovenianSlovenia                0x01
#define kNtSublangSpanish                          0x01
#define kNtSublangSpanishMexican                   0x02
#define kNtSublangSpanishModern                    0x03
#define kNtSublangSpanishGuatemala                 0x04
#define kNtSublangSpanishCostaRica                 0x05
#define kNtSublangSpanishPanama                    0x06
#define kNtSublangSpanishDominicanRepublic         0x07
#define kNtSublangSpanishVenezuela                 0x08
#define kNtSublangSpanishColombia                  0x09
#define kNtSublangSpanishPeru                      0x0a
#define kNtSublangSpanishArgentina                 0x0b
#define kNtSublangSpanishEcuador                   0x0c
#define kNtSublangSpanishChile                     0x0d
#define kNtSublangSpanishUruguay                   0x0e
#define kNtSublangSpanishParaguay                  0x0f
#define kNtSublangSpanishBolivia                   0x10
#define kNtSublangSpanishElSalvador                0x11
#define kNtSublangSpanishHonduras                  0x12
#define kNtSublangSpanishNicaragua                 0x13
#define kNtSublangSpanishPuertoRico                0x14
#define kNtSublangSpanishUs                        0x15
#define kNtSublangSwahiliKenya                     0x01
#define kNtSublangSwedish                          0x01
#define kNtSublangSwedishFinland                   0x02
#define kNtSublangSyriacSyria                      0x01
#define kNtSublangTajikTajikistan                  0x01
#define kNtSublangTamazightAlgeriaLatin            0x02
#define kNtSublangTamazightMoroccoTifinagh         0x04
#define kNtSublangTamilIndia                       0x01
#define kNtSublangTamilSriLanka                    0x02
#define kNtSublangTatarRussia                      0x01
#define kNtSublangTeluguIndia                      0x01
#define kNtSublangThaiThailand                     0x01
#define kNtSublangTibetanPrc                       0x01
#define kNtSublangTigrignaEritrea                  0x02
#define kNtSublangTigrinyaEritrea                  0x02
#define kNtSublangTigrinyaEthiopia                 0x01
#define kNtSublangTswanaBotswana                   0x02
#define kNtSublangTswanaSouthAfrica                0x01
#define kNtSublangTurkishTurkey                    0x01
#define kNtSublangTurkmenTurkmenistan              0x01
#define kNtSublangUighurPrc                        0x01
#define kNtSublangUkrainianUkraine                 0x01
#define kNtSublangUpperSorbianGermany              0x01
#define kNtSublangUrduPakistan                     0x01
#define kNtSublangUrduIndia                        0x02
#define kNtSublangUzbekLatin                       0x01
#define kNtSublangUzbekCyrillic                    0x02
#define kNtSublangValencianValencia                0x02
#define kNtSublangVietnameseVietnam                0x01
#define kNtSublangWelshUnitedKingdom               0x01
#define kNtSublangWolofSenegal                     0x01
#define kNtSublangXhosaSouthAfrica                 0x01
#define kNtSublangYakutRussia                      0x01
#define kNtSublangYiPrc                            0x01
#define kNtSublangYorubaNigeria                    0x01
#define kNtSublangZuluSouthAfrica                  0x01

#endif /* COSMOPOLITAN_LIBC_NT_ENUM_LANG_H_ */
