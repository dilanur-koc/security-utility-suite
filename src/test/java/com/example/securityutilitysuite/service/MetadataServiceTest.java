package com.example.securityutilitysuite.service;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.example.securityutilitysuite.dto.MetadataReadResponse;

/**
 * Bayt-seviyesi strip mantigini, gercek EXIF/PNG/WEBP encoder'lari olmadan
 * elle insa edilmis minimal dosyalarla dogrular. Amac: metadata tasiyan
 * segment/chunk'in kaybolmasi, geri kalan her seyin (goruntu verisi dahil)
 * degismemesi.
 */
class MetadataServiceTest {

    private final MetadataService service = new MetadataService();

    // ------------------------------------------------------------------
    // JPEG
    // ------------------------------------------------------------------

    @Test
    void jpeg_temizlemeAppOneExifSegmentiniKaldirir() throws IOException {
        byte[] jpeg = buildJpegWithApp1AndApp0();

        MockMultipartFile file = new MockMultipartFile("file", "photo.jpg", "image/jpeg", jpeg);
        MetadataService.CleanedFile result = service.clean(file);

        assertThat(result.format()).isEqualTo(MetadataService.ImageFormat.JPEG);
        String hex = toHex(result.data());

        // APP1 marker (FFE1) tamamen kaybolmus olmali
        assertThat(hex).doesNotContain("ffe1");
        // "Exif" imzasi da onunla birlikte gitmis olmali
        assertThat(new String(result.data(), StandardCharsets.ISO_8859_1)).doesNotContain("Exif");
        // APP0/JFIF (metadata tasimaz) korunmus olmali
        assertThat(hex).contains("ffe0");
        // SOI ve EOI korunmus olmali
        assertThat(result.data()[0] & 0xFF).isEqualTo(0xFF);
        assertThat(result.data()[1] & 0xFF).isEqualTo(0xD8);
        byte[] d = result.data();
        assertThat(d[d.length - 2] & 0xFF).isEqualTo(0xFF);
        assertThat(d[d.length - 1] & 0xFF).isEqualTo(0xD9);
    }

    @Test
    void jpeg_sikistirilmisTaramaVerisiDegismedenKorunur() throws IOException {
        byte[] jpeg = buildJpegWithApp1AndApp0();
        MockMultipartFile file = new MockMultipartFile("file", "photo.jpg", "image/jpeg", jpeg);

        byte[] cleaned = service.clean(file).data();

        // Scan verisi (SOS sonrasi) elle koydugumuz imzayi tasimali
        assertThat(new String(cleaned, StandardCharsets.ISO_8859_1)).contains("SCANDATA");
    }

    // ------------------------------------------------------------------
    // PNG
    // ------------------------------------------------------------------

    @Test
    void png_temizlemeTextChunkiKaldirirIhdrVeIdatiKorur() throws IOException {
        byte[] png = buildPngWithTextChunk();
        MockMultipartFile file = new MockMultipartFile("file", "photo.png", "image/png", png);

        MetadataService.CleanedFile result = service.clean(file);

        assertThat(result.format()).isEqualTo(MetadataService.ImageFormat.PNG);
        String content = new String(result.data(), StandardCharsets.ISO_8859_1);
        assertThat(content).doesNotContain("tEXt");
        assertThat(content).doesNotContain("gizli-yorum");
        assertThat(content).contains("IHDR");
        assertThat(content).contains("IDAT");
        assertThat(content).contains("IEND");
    }

    // ------------------------------------------------------------------
    // WEBP
    // ------------------------------------------------------------------

    @Test
    void webp_temizlemeExifChunkiKaldirirVp8iKorur() throws IOException {
        byte[] webp = buildWebpWithExifChunk();
        MockMultipartFile file = new MockMultipartFile("file", "photo.webp", "image/webp", webp);

        MetadataService.CleanedFile result = service.clean(file);

        assertThat(result.format()).isEqualTo(MetadataService.ImageFormat.WEBP);
        String content = new String(result.data(), StandardCharsets.ISO_8859_1);
        assertThat(content).doesNotContain("EXIF");
        assertThat(content).contains("VP8 ");
        // RIFF header hala gecerli olmali
        assertThat(result.data()[0]).isEqualTo((byte) 'R');
        assertThat(result.data()[8]).isEqualTo((byte) 'W');
    }

    // ------------------------------------------------------------------
    // Format tespiti / hata durumlari
    // ------------------------------------------------------------------

    @Test
    void desteklenmeyenFormatReddedilir() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "not-an-image.txt", "text/plain", "hello world".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> service.clean(file))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Desteklenmeyen");
    }

    @Test
    void uzantiDegilMagicByteGuvenilir() throws IOException {
        // .png uzantili ama gercekte JPEG olan bir dosya — format yine de dogru tespit edilmeli
        byte[] jpeg = buildJpegWithApp1AndApp0();
        MockMultipartFile file = new MockMultipartFile("file", "sahte.png", "image/png", jpeg);

        MetadataService.CleanedFile result = service.clean(file);

        assertThat(result.format()).isEqualTo(MetadataService.ImageFormat.JPEG);
    }

    // ------------------------------------------------------------------
    // Test fixture insaacilari
    // ------------------------------------------------------------------

    private byte[] buildJpegWithApp1AndApp0() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xFF); out.write(0xD8); // SOI

        // APP1 (Exif) — temizlenmesi gereken segment
        byte[] exifPayload = "Exif\0\0FAKE-TIFF-HEADER-AND-GPS-DATA".getBytes(StandardCharsets.ISO_8859_1);
        writeSegment(out, 0xE1, exifPayload);

        // APP0 (JFIF) — korunmasi gereken segment
        byte[] jfifPayload = "JFIF\0\u0001\u0001\u0000\u0000\u0001\u0000\u0001\u0000\u0000".getBytes(StandardCharsets.ISO_8859_1);
        writeSegment(out, 0xE0, jfifPayload);

        // SOS — minimal baslik + sahte sikistirilmis veri
        byte[] sosHeader = {0x01, 0x00, 0x00, 0x00}; // gercek degil, sadece uzunluk dolgusu
        writeSegment(out, 0xDA, sosHeader);
        out.write("SCANDATA".getBytes(StandardCharsets.ISO_8859_1));

        out.write(0xFF); out.write(0xD9); // EOI
        return out.toByteArray();
    }

    private void writeSegment(ByteArrayOutputStream out, int marker, byte[] payload) throws IOException {
        out.write(0xFF);
        out.write(marker);
        int len = payload.length + 2; // uzunluk alaninin kendisi dahil
        out.write((len >> 8) & 0xFF);
        out.write(len & 0xFF);
        out.write(payload);
    }

    private byte[] buildPngWithTextChunk() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A});

        writePngChunk(out, "IHDR", new byte[13]); // dummy IHDR govdesi
        writePngChunk(out, "tEXt", "Comment\0gizli-yorum".getBytes(StandardCharsets.ISO_8859_1));
        writePngChunk(out, "IDAT", new byte[]{1, 2, 3, 4});
        writePngChunk(out, "IEND", new byte[0]);

        return out.toByteArray();
    }

    private void writePngChunk(ByteArrayOutputStream out, String type, byte[] data) throws IOException {
        int len = data.length;
        out.write((len >> 24) & 0xFF);
        out.write((len >> 16) & 0xFF);
        out.write((len >> 8) & 0xFF);
        out.write(len & 0xFF);
        out.write(type.getBytes(StandardCharsets.US_ASCII));
        out.write(data);
        out.write(new byte[]{0, 0, 0, 0}); // CRC — strip mantigi dogrulamiyor, sahte deger yeterli
    }

    private byte[] buildWebpWithExifChunk() throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeWebpChunk(body, "VP8 ", new byte[]{1, 2, 3, 4});
        writeWebpChunk(body, "EXIF", "FAKE-EXIF-DATA".getBytes(StandardCharsets.ISO_8859_1));
        byte[] bodyBytes = body.toByteArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write('R'); out.write('I'); out.write('F'); out.write('F');
        long riffSize = 4 + bodyBytes.length;
        out.write((int) (riffSize & 0xFF));
        out.write((int) ((riffSize >> 8) & 0xFF));
        out.write((int) ((riffSize >> 16) & 0xFF));
        out.write((int) ((riffSize >> 24) & 0xFF));
        out.write('W'); out.write('E'); out.write('B'); out.write('P');
        out.write(bodyBytes);

        return out.toByteArray();
    }

    private void writeWebpChunk(ByteArrayOutputStream out, String fourCc, byte[] data) throws IOException {
        out.write(fourCc.getBytes(StandardCharsets.US_ASCII));
        int len = data.length;
        out.write(len & 0xFF);
        out.write((len >> 8) & 0xFF);
        out.write((len >> 16) & 0xFF);
        out.write((len >> 24) & 0xFF);
        out.write(data);
        if (len % 2 != 0) {
            out.write(0); // padding
        }
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Test
    void gercekFotografiKontrolEt() throws Exception {
        java.io.File f = new java.io.File("/home/dila/Downloads/sherry-christian-8Myh76_3M2U-unsplash.jpg");
        byte[] bytes = java.nio.file.Files.readAllBytes(f.toPath());
        MockMultipartFile file = new MockMultipartFile("file", f.getName(), "image/jpeg", bytes);
        MetadataReadResponse r = service.read(file);
        System.out.println("=== SONUC ===");
        System.out.println("Format: " + r.detectedFormat());
        System.out.println("tagCount: " + r.tagCount());
        System.out.println("hasGps: " + r.hasGps());
        // === BURADAN İTİBAREN YENİ EKLENEN KISIM ===
        System.out.println("dosya boyutu: " + bytes.length);
        com.drew.metadata.Metadata dogrudan = com.drew.imaging.ImageMetadataReader.readMetadata(f);
        System.out.println("kutuphane dogrudan (File ile) directory sayisi: " + dogrudan.getDirectoryCount());
        for (com.drew.metadata.Directory d : dogrudan.getDirectories()) {
            System.out.println("  DIR: " + d.getName() + " (" + d.getTagCount() + " etiket)");
            if (d.hasErrors()) {
                for (String e : d.getErrors()) System.out.println("    HATA: " + e);
            }
        }
        // === YENİ EKLENEN İKİNCİ KISIM ===
        java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(bytes);
        com.drew.metadata.Metadata streamIle = com.drew.imaging.ImageMetadataReader.readMetadata(bais);
        System.out.println("kutuphane InputStream ile directory sayisi: " + streamIle.getDirectoryCount());
        for (com.drew.metadata.Directory d : streamIle.getDirectories()) {
            System.out.println("  DIR: " + d.getName() + " (" + d.getTagCount() + " etiket)");
        }
        // === YENİ EKLENEN KISIM SONU ===
        r.tags().forEach(t -> System.out.println("  " + t.directory() + " / " + t.tagName() + " = " + t.description()));
    }



}
