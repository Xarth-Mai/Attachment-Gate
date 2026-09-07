package detect

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func extendedImageFormat(kind Type) string {
	switch kind {
	case TypeImageGIF:
		return "GIF"
	case TypeImageBMP:
		return "BMP"
	case TypeImageTIFF:
		return "TIFF"
	case TypeImageHEIF:
		return "HEIF"
	case TypeImageAVIF:
		return "AVIF"
	default:
		return ""
	}
}

// Extended formats are opt-in and require host decoders; existing profiles stay dependency-compatible
func CheckImageDecoders(ctx context.Context, allowed []string) error {
	var formats []string
	for _, kind := range allowed {
		if format := extendedImageFormat(Type(kind)); format != "" {
			formats = append(formats, format)
		}
	}
	if len(formats) == 0 {
		return nil
	}
	if err := exec.CommandContext(ctx, "python3", "-I", "-c", imageDecoderProbe, strings.Join(formats, ",")).Run(); err != nil {
		return errors.New("extended image decoders unavailable: require Python Pillow with configured formats and pillow-heif for HEIF")
	}
	return nil
}

const imageDecoderProbe = `
import sys
from PIL import Image
formats = sys.argv[1].split(',')
if 'HEIF' in formats:
    from pillow_heif import register_heif_opener
    register_heif_opener()
Image.init()
assert all(f in Image.OPEN for f in formats)
`

const imageHeaderProbe = `
import sys, warnings, resource
resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
from PIL import Image
expected = sys.argv[2]
if expected == 'HEIF':
    from pillow_heif import register_heif_opener
    register_heif_opener()
Image.MAX_IMAGE_PIXELS = int(sys.argv[3])
warnings.simplefilter('error', Image.DecompressionBombWarning)
try:
    with Image.open(sys.argv[1]) as im:
        assert im.format == expected
        assert im.width > 0 and im.height > 0
        if im.width * im.height > Image.MAX_IMAGE_PIXELS:
            sys.exit(3)
except (Image.DecompressionBombWarning, Image.DecompressionBombError):
    sys.exit(3)
`

func validateExtendedImage(ctx context.Context, filePath, format string, maxPixels uint64) error {
	err := exec.CommandContext(ctx, "python3", "-I", "-c", imageHeaderProbe, filePath, format, strconv.FormatUint(maxPixels, 10)).Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 3 {
		return ErrImageDimensionsExceeded
	}
	return fmt.Errorf("%w: cannot read %s image header", ErrInvalidImage, format)
}
