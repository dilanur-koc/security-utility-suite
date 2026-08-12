package com.example.securityutilitysuite.model;

import com.example.securityutilitysuite.enums.NotificationSeverity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Kullaniciya gosterilecek uygulama ici bildirim.
 *
 * Bildirimler YALNIZCA degisiklik veya sorun oldugunda uretilir. Her
 * kontrolde bildirim uretmek, kullaniciyi kisa surede korlestirir
 * (alarm yorgunlugu) ve arac guvenilirligini kaybeder.
 */
@Entity
@Table(name = "notifications", indexes = {
        @Index(name = "idx_notif_owner_read", columnList = "owner_id, is_read, created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Notification extends OwnedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, length = 1000)
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private NotificationSeverity severity;

    /** Ilgili izleme hedefi; genel bildirimlerde null olabilir. */
    @Column(name = "target_id")
    private Long targetId;

    @Column(name = "is_read", nullable = false)
    private boolean read;
}
