package pqstore

import (
	"github.com/klauspost/compress/zstd"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
)

// zstdCodec is parquet-go's zstd codec with encoders that are kept. Its
// own pool loses them at every garbage collection, and each new encoder
// allocated a 16 MB history (8 MB window, doubled): about 400 MB per
// busy-load benchmark run. A 1 MiB window costs nothing in compression,
// since a data page is at most 256 KiB (DefaultPageBufferSize) and each
// is compressed on its own.
type zstdCodec struct {
	encoders chan *zstd.Encoder
}

var zstdPages = &zstdCodec{encoders: make(chan *zstd.Encoder, 4)}

func (c *zstdCodec) String() string                           { return "ZSTD" }
func (c *zstdCodec) CompressionCodec() format.CompressionCodec { return format.Zstd }

func (c *zstdCodec) Encode(dst, src []byte) ([]byte, error) {
	var e *zstd.Encoder
	select {
	case e = <-c.encoders:
	default:
		var err error
		e, err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithWindowSize(1<<20), zstd.WithZeroFrames(true), zstd.WithEncoderCRC(false))
		if err != nil {
			return dst, err
		}
	}
	dst = e.EncodeAll(src, dst[:0])
	select {
	case c.encoders <- e:
	default: // more were in use at once than are kept
	}
	return dst, nil
}

// Decode is not used by the writers; readers pick the codec from the file.
func (c *zstdCodec) Decode(dst, src []byte) ([]byte, error) { return parquet.Zstd.Decode(dst, src) }
