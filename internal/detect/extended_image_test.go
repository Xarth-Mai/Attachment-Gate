package detect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExtendedImageFormats(t *testing.T) {
	for _, tc := range []struct {
		format, ext string
		kind        Type
	}{
		{"MPO", ".jpeg", TypeImageJPEG}, {"MPO", ".mpo", TypeImageJPEG},
		{"HEIF", ".heic", TypeImageHEIF}, {"AVIF", ".avif", TypeImageAVIF},
		{"GIF", ".gif", TypeImageGIF}, {"BMP", ".bmp", TypeImageBMP}, {"TIFF", ".tiff", TypeImageTIFF},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			ctx := context.Background()
			file := filepath.Join(t.TempDir(), "source"+tc.ext)
			script := `from PIL import Image, MpoImagePlugin
from pillow_heif import register_heif_opener
import sys
register_heif_opener()
im = Image.new('RGB',(16,12),(220,30,10))
kwargs = dict(save_all=True, append_images=[im]) if sys.argv[2] == 'MPO' else {}
im.save(sys.argv[1], format=sys.argv[2], **kwargs)`
			if out, err := exec.Command("python3", "-I", "-c", script, file, tc.format).CombinedOutput(); err != nil {
				t.Fatalf("fixture: %v %s", err, out)
			}
			got, err := (Detector{MaxImagePixels: 192}).Detect(ctx, file)
			if err != nil || got.Type != tc.kind {
				t.Fatalf("Detect = %+v %v", got, err)
			}
			_, err = (Detector{MaxImagePixels: 191}).Detect(ctx, file)
			if !errors.Is(err, ErrImageDimensionsExceeded) {
				t.Fatalf("pixel limit: %v", err)
			}
			if err := os.WriteFile(file, []byte("not an image"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := validateImage(ctx, file, tc.kind, 192); !errors.Is(err, ErrInvalidImage) {
				t.Fatalf("invalid image: %v", err)
			}
		})
	}
}

func TestExtendedDecoderDependencies(t *testing.T) {
	ctx := context.Background()
	if err := CheckImageDecoders(ctx, []string{"image_heif", "image_avif", "image_tiff"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := CheckImageDecoders(ctx, []string{"image_png", "image_jpeg"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckImageDecoders(ctx, []string{"image_heif"}); err == nil {
		t.Fatal("missing decoder must fail")
	}
}
