// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package precompile

import (
	"github.com/ava-labs/avalanchego/codec"
	"github.com/ava-labs/avalanchego/codec/linearcodec"
	"github.com/ava-labs/avalanchego/utils/units"
	"github.com/ava-labs/avalanchego/utils/wrappers"
	warp "github.com/ava-labs/subnet-evm/precompile/contracts/warpmessenger"
)

const (
	Version        = uint16(0)
	maxMessageSize = 1 * units.MiB
)

var (
	Codec codec.Manager
)

func init() {
	Codec = codec.NewManager(maxMessageSize)
	c := linearcodec.NewDefault()

	errs := wrappers.Errs{}
	errs.Add(
		// Warp messenger types
		c.RegisterType(warp.WarpMessage{}),

		Codec.RegisterCodec(Version, c),
	)

	if errs.Errored() {
		panic(errs.Err)
	}
}
