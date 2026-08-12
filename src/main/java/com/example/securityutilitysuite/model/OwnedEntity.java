package com.example.securityutilitysuite.model;

import jakarta.persistence.Column;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * Bir kullaniciya AIT olan kayitlarin ortak ust sinifi.
 *
 * NEDEN ORTAK SINIF:
 * Sahiplik alanini her entity'ye tek tek eklemek, birinde unutulmasi
 * demektir — ve unutulan yer dogrudan bir IDOR acigi olur (baskasinin
 * kaydini id tahmin ederek gorme/silme). Tek yerde tanimlayip miras
 * vermek bu riski ortadan kaldirir.
 *
 * {@code owner} alani {@code nullable = false}: veritabani seviyesinde de
 * sahipsiz kayit olusturulamaz. Kod tarafinda bir kontrol atlansa bile
 * kayit basarisiz olur.
 *
 * LAZY yukleme secildi: kayit listelenirken kullanicinin tum bilgileri
 * gereksiz yere cekilmesin.
 */
@MappedSuperclass
@Getter
@Setter
public abstract class OwnedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
