package com.example.securityutilitysuite.service;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import com.drew.metadata.exif.GpsDirectory;
import com.example.securityutilitysuite.dto.Finding;
import com.example.securityutilitysuite.dto.MetadataReadResponse;
import com.example.securityutilitysuite.dto.MetadataTag;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import com.drew.imaging.ImageProcessingException;

/**
 * v1 kapsami: JPEG, PNG, WEBP icin metadata okuma ve temizleme.
 *
 * Tasarim notlari:
 * - Format tespiti dosya UZANTISINA degil magic byte'lara gore yapilir.
 *   Bir guvenlik aracinda uzantiya guvenmek yaniltici olur (birisi .png
 *   uzantili bir JPEG yukleyebilir) — gercek format ilk baytlardan okunur.
 * - Temizleme, dosyayi yeniden encode ETMEZ; yalnizca metadata tasiyan
 *   segment/chunk'lari kaldirip geri kalan baytlari oldugu gibi kopyalar.
 *   Bu yuzden goruntu kalitesi/piksel verisi hic degismez.
 * - JPEG'de SOS (Start of Scan) marker'indan sonraki tum bayt aynen
 *   kopyalanir; sikistirilmis tarama verisi icinde marker ayristirmaya
 *   calismak (0xFF00 stuffing, RST marker'lari) gereksiz risk tasir.
 * - WEBP'te VP8X chunk'indaki EXIF/XMP bayrak bitleri KASITLI OLARAK
 *   degistirilmez: ilgili chunk zaten kaldirildigi icin veri sizmaz,
 *   ama bayrak bitlerini yanlis temizlemek (Alpha/Anim bitleriyle
 *   karismasi) dosyayi bozma riski tasir.
 */
@Service
public class MetadataService {

    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] PNG_MAGIC =
            {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

    /** Metadata tasiyabilen JPEG marker'lari: APP1 (Exif/XMP), APP13 (IPTC/Photoshop), COM (yorum). */
    private static final Set<Integer> JPEG_STRIP_MARKERS = Set.of(0xE1, 0xED, 0xFE);

    /** Metadata tasiyan PNG ancillary chunk turleri. */
    private static final Set<String> PNG_STRIP_CHUNKS =
            Set.of("tEXt", "zTXt", "iTXt", "eXIf", "tIME");

    private static final Set<String> WEBP_STRIP_CHUNKS = Set.of("EXIF", "XMP ");

    public enum ImageFormat { JPEG, PNG, WEBP }

    // ------------------------------------------------------------------
    // Okuma
    // ------------------------------------------------------------------

    public MetadataReadResponse read(MultipartFile file) throws IOException {
        byte[] data = file.getBytes();
        ImageFormat format = detectFormat(data)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Desteklenmeyen veya taninmayan dosya formati. "
                                + "v1 yalnizca JPEG, PNG ve WEBP destekler."));

        List<MetadataTag> tags = new ArrayList<>();
        Double lat = null;
        Double lon = null;

        Metadata metadata;
        try {
            metadata = ImageMetadataReader.readMetadata(new ByteArrayInputStream(data));
        } catch (ImageProcessingException ex) {
            throw new IllegalArgumentException("Dosya metadata için ayrıştırılamadı: " + ex.getMessage());
        }

        for (Directory directory : metadata.getDirectories()) {
            for (Tag tag : directory.getTags()) {
                tags.add(new MetadataTag(directory.getName(), tag.getTagName(), tag.getDescription()));
            }
        }

        GpsDirectory gps = metadata.getFirstDirectoryOfType(GpsDirectory.class);
        boolean hasGps = false;
        if (gps != null && gps.getGeoLocation() != null && !gps.getGeoLocation().isZero()) {
            hasGps = true;
            lat = gps.getGeoLocation().getLatitude();
            lon = gps.getGeoLocation().getLongitude();
        }

        List<Finding> findings = findings(tags, hasGps);

        return new MetadataReadResponse(
                file.getOriginalFilename(),
                format.name(),
                data.length,
                tags.size(),
                hasGps,
                lat,
                lon,
                tags,
                findings
        );
    }

    private List<Finding> findings(List<MetadataTag> tags, boolean hasGps) {
        List<Finding> f = new ArrayList<>();

        if (hasGps) {
            f.add(Finding.critical("Dosyada GPS konum bilgisi bulundu — "
                    + "cekim yapilan yeri dogrudan ifsa ediyor."));
        }

        boolean hasDeviceInfo = tags.stream().anyMatch(t ->
                t.tagName() != null
                        && (t.tagName().equalsIgnoreCase("Model")
                        || t.tagName().equalsIgnoreCase("Make")));
        if (hasDeviceInfo) {
            f.add(Finding.medium("Cihaz uretici/model bilgisi bulundu."));
        }

        boolean hasSoftware = tags.stream().anyMatch(t ->
                t.tagName() != null && t.tagName().equalsIgnoreCase("Software"));
        if (hasSoftware) {
            f.add(Finding.low("Duzenleme yazilimi/versiyon bilgisi bulundu."));
        }

        if (tags.isEmpty()) {
            f.add(Finding.low("Herhangi bir metadata bulunamadi — dosya zaten temiz olabilir."));
        }

        return f;
    }

    // ------------------------------------------------------------------
    // Temizleme
    // ------------------------------------------------------------------

    /** Temizlenmis dosya baytlari ve tespit edilen format. */
    public record CleanedFile(byte[] data, ImageFormat format) {
    }

    public CleanedFile clean(MultipartFile file) throws IOException {
        byte[] data = file.getBytes();
        ImageFormat format = detectFormat(data)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Desteklenmeyen veya taninmayan dosya formati. "
                                + "v1 yalnizca JPEG, PNG ve WEBP destekler."));

        byte[] cleaned = switch (format) {
            case JPEG -> stripJpeg(data);
            case PNG -> stripPng(data);
            case WEBP -> stripWebp(data);
        };

        return new CleanedFile(cleaned, format);
    }

    private byte[] stripJpeg(byte[] data) {
        if (data.length < 4 || (data[0] & 0xFF) != 0xFF || (data[1] & 0xFF) != 0xD8) {
            throw new IllegalArgumentException("Gecerli bir JPEG dosyasi degil (SOI eksik)");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
        out.write(data[0]);
        out.write(data[1]);
        int i = 2;

        while (i < data.length) {
            if ((data[i] & 0xFF) != 0xFF) {
                throw new IllegalArgumentException("Bozuk JPEG: beklenen marker bulunamadi (ofset " + i + ")");
            }
            // Marker onunde dolgu (0xFF) baytlari olabilir.
            int markerStart = i;
            while (i < data.length && (data[i] & 0xFF) == 0xFF) {
                i++;
            }
            if (i >= data.length) {
                break;
            }
            int marker = data[i] & 0xFF;
            i++;

            // Standalone marker'lar (uzunluk alani tasimaz): TEM(0x01), RST0-7(0xD0-D7), SOI/EOI zaten islendi.
            if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                out.write(0xFF);
                out.write(marker);
                continue;
            }

            if (marker == 0xD9) { // EOI
                out.write(0xFF);
                out.write(marker);
                break;
            }

            if (i + 1 >= data.length) {
                throw new IllegalArgumentException("Bozuk JPEG: segment uzunlugu okunamadi");
            }
            int segLength = ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            if (segLength < 2 || i + segLength > data.length) {
                throw new IllegalArgumentException("Bozuk JPEG: gecersiz segment uzunlugu (ofset " + markerStart + ")");
            }

            boolean strip = JPEG_STRIP_MARKERS.contains(marker);
            if (!strip) {
                out.write(0xFF);
                out.write(marker);
                out.write(data, i, segLength);
            }
            i += segLength;

            if (marker == 0xDA) {
                // SOS marker+segmenti yukaridaki genel dalda zaten yazildi (SOS hicbir
                // zaman strip edilmiyor). Geri kalan her sey — sikistirilmis tarama
                // verisi, icindeki RST marker'lari ve EOI — aynen kopyalanir.
                out.write(data, i, data.length - i);
                break;
            }
        }

        return out.toByteArray();
    }

    private byte[] stripPng(byte[] data) {
        if (data.length < 8) {
            throw new IllegalArgumentException("Gecerli bir PNG dosyasi degil");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
        out.write(data, 0, 8); // imza
        int i = 8;

        while (i + 8 <= data.length) {
            long length = ((long) (data[i] & 0xFF) << 24) | ((data[i + 1] & 0xFF) << 16)
                    | ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
            String type = new String(data, i + 4, 4, java.nio.charset.StandardCharsets.US_ASCII);

            int chunkTotal = (int) (8 + length + 4); // length+type+data+crc
            if (length < 0 || i + chunkTotal > data.length) {
                throw new IllegalArgumentException("Bozuk PNG: gecersiz chunk uzunlugu (" + type + ")");
            }

            if (!PNG_STRIP_CHUNKS.contains(type)) {
                out.write(data, i, chunkTotal);
            }

            i += chunkTotal;
            if (type.equals("IEND")) {
                break;
            }
        }

        return out.toByteArray();
    }

    private byte[] stripWebp(byte[] data) {
        if (data.length < 12
                || data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F'
                || data[8] != 'W' || data[9] != 'E' || data[10] != 'B' || data[11] != 'P') {
            throw new IllegalArgumentException("Gecerli bir WEBP dosyasi degil");
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream(data.length);
        int i = 12;
        while (i + 8 <= data.length) {
            String fourCc = new String(data, i, 4, java.nio.charset.StandardCharsets.US_ASCII);
            long size = (data[i + 4] & 0xFFL) | ((data[i + 5] & 0xFFL) << 8)
                    | ((data[i + 6] & 0xFFL) << 16) | ((data[i + 7] & 0xFFL) << 24);
            int padded = (int) (size + (size % 2)); // chunk'lar cift sayida bayta hizalanir
            int chunkTotal = 8 + padded;

            if (size < 0 || i + chunkTotal > data.length) {
                throw new IllegalArgumentException("Bozuk WEBP: gecersiz chunk uzunlugu (" + fourCc + ")");
            }

            if (!WEBP_STRIP_CHUNKS.contains(fourCc)) {
                body.write(data, i, chunkTotal);
            }

            i += chunkTotal;
        }

        byte[] bodyBytes = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream(12 + bodyBytes.length);
        out.write('R'); out.write('I'); out.write('F'); out.write('F');
        long riffSize = 4L + bodyBytes.length; // 'WEBP' + chunk'lar
        out.write((int) (riffSize & 0xFF));
        out.write((int) ((riffSize >> 8) & 0xFF));
        out.write((int) ((riffSize >> 16) & 0xFF));
        out.write((int) ((riffSize >> 24) & 0xFF));
        out.write('W'); out.write('E'); out.write('B'); out.write('P');
        out.write(bodyBytes, 0, bodyBytes.length);

        return out.toByteArray();
    }

    // ------------------------------------------------------------------
    // Format tespiti
    // ------------------------------------------------------------------

    private java.util.Optional<ImageFormat> detectFormat(byte[] data) {
        if (startsWith(data, JPEG_MAGIC)) {
            return java.util.Optional.of(ImageFormat.JPEG);
        }
        if (startsWith(data, PNG_MAGIC)) {
            return java.util.Optional.of(ImageFormat.PNG);
        }
        if (data.length >= 12
                && data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F'
                && data[8] == 'W' && data[9] == 'E' && data[10] == 'B' && data[11] == 'P') {
            return java.util.Optional.of(ImageFormat.WEBP);
        }
        return java.util.Optional.empty();
    }

    private boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}


