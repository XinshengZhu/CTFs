let regex = /^wctf{(((?=(.{5}4))(((?=(.{2}g.(l)))(r3)).(?<=(r)..)u\7)).\9).{12}(\x5f)(?<=(\1(?:\10)(?:((?=(.{2}p[^-]([^-])5))(3x)).((?=(.{2}(\x355)))(((?=(.3))r)))...3{0,0}))(\x31)(0)n5.)m\23{1,1}(?=.(..))\8_l(\22)k(?:\24)\25r(?=\11).{8}[\w\d]{7}i..s(?<=\23n.)_smh_((?=(.{6}(z)((?=(.{2}9))((?<=z)(?=........r)(?<=(K)....).(4)(?<=O.{5}(.).))).TC(?=.b)))(Q.\32(?=.{4}i).E(?=.{9}L)f)).{6}\28...(?<=...U.{12})}$/

const flag = 'wctf{r3gul4r_3xpr35510n5_m0r3_l1k3_1rr3gul4r_3xpr355i0ns_smh_QOKUEfzi49TCzbLr}'

const match = flag.match(regex);

if (match) {
    console.log('Successfully matched!');
    match.forEach((group, index) => {
        console.log(`Captured Group ${index}: ${group}`);
    });
} else {
    console.log('No match found');
}