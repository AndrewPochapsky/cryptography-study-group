use std::ops::{Add, Neg};

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{Num, Zero};

enum Error {
    NotSmooth,
}

#[derive(PartialEq, Eq, Clone)]
pub enum EllipticCurveType {
    Weierstrass,
    Montgomery,
}

#[derive(Eq, Clone)]
pub struct EllipticCurve {
    name: String,
    order: BigUint,
    a2: BigInt,
    a4: BigInt,
    a6: BigInt,
    p: BigUint,
    elliptic_curve_type: EllipticCurveType,
}

impl PartialEq for EllipticCurve {
    fn eq(&self, other: &Self) -> bool {
        self.a2 == other.a2 && self.a4 == other.a4 && self.a6 == other.a6 && self.p == other.p
    }
}

impl Default for EllipticCurve {
    fn default() -> Self {
        let name = String::from("Secp256k1");
        let order = BigUint::from(2u32).pow(256)
            - BigUint::from_str_radix("014551231950b75fc4402da1732fc9bebf", 16).unwrap();
        let modulus =
            BigUint::from(2u32).pow(256) - BigUint::from(2u32).pow(32) - BigUint::from(977u32);
        let coefficients = [Zero::zero(), Zero::zero(), BigInt::from(7u32)];

        Self::new(name, order, modulus, coefficients)
    }
}

impl EllipticCurve {
    fn new(name: String, order: BigUint, modulus: BigUint, coefficients: [BigInt; 3]) -> Self {
        let elliptic_curve_type = if coefficients[0] == Zero::zero() {
            EllipticCurveType::Weierstrass
        } else {
            EllipticCurveType::Montgomery
        };

        Self {
            name,
            order,
            a2: coefficients[0].clone(),
            a4: coefficients[1].clone(),
            a6: coefficients[2].clone(),
            p: modulus,
            elliptic_curve_type,
        }
    }

    fn discriminant(&self) -> BigInt {
        let b2: BigInt = 2 * &self.a2;
        let b4: BigInt = 2 * &self.a4;
        let b6: BigInt = 4 * &self.a6;
        let b8: BigInt = &b2 * &self.a6 - &self.a4.pow(2);

        -b8 * (b2.pow(2)) - 8 * (b4.pow(3)) - 27 * (b6.pow(2)) + 9 * b2 * b4 * b6
    }

    fn is_smooth(&self) -> Result<bool, Error> {
        if self.discriminant().is_zero() {
            return Err(Error::NotSmooth);
        }
        Ok(true)
    }
}

#[derive(PartialEq, Eq, Clone)]
pub enum PointType {
    Regular,
    Infinite,
}

#[derive(PartialEq, Eq, Clone)]
pub struct Point {
    x: Option<BigInt>,
    y: Option<BigInt>,
    curve: EllipticCurve,
    point_type: PointType,
}

impl Default for Point {
    fn default() -> Self {
        Self::new(EllipticCurve::default(), None, None)
    }
}

impl Point {
    fn new(curve: EllipticCurve, x: Option<BigInt>, y: Option<BigInt>) -> Self {
        let point_type = if x.is_some() {
            PointType::Regular
        } else {
            PointType::Infinite
        };
        Self {
            x,
            y,
            curve,
            point_type,
        }
    }
}

impl Neg for Point {
    type Output = Self;
    fn neg(self) -> Self::Output {
        if self.point_type == PointType::Regular {
            let y = if let Some(y) = self.y {
                Some((-y) % self.curve.p.to_bigint().unwrap())
            } else {
                None
            };
            Point::new(self.curve, self.x, y)
        } else {
            // Infinite point
            self
        }
    }
}

impl Add for Point {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        if rhs.point_type == PointType::Infinite {
            return self;
        } else if self.point_type == PointType::Infinite {
            return rhs;
        } else if rhs == -self.clone() {
            return Point::new(self.curve, None, None);
        }
        let (_inv_l, lambda) = if self == rhs {
            if self.y == Some(Zero::zero()) {
                return Point::new(self.curve, None, None);
            }
            let l: BigInt = 2 * self.y.as_ref().unwrap();
            let inv_l = l.modpow(&BigInt::from(-1i32), &self.curve.p.to_bigint().unwrap());
            let lambda: BigInt = (3 * self.x.as_ref().unwrap().pow(2u32)
                + 2 * &self.curve.a2 * self.x.as_ref().unwrap()
                + &self.curve.a4)
                * &inv_l;
            (inv_l, lambda)
        } else {
            let inv_l: BigInt = (rhs.x.as_ref().unwrap() - self.x.as_ref().unwrap())
                .modpow(&BigInt::from(-1), &self.curve.p.to_bigint().unwrap());
            let lambda = (rhs.y.unwrap() - self.y.as_ref().unwrap()) * &inv_l;
            (inv_l, lambda)
        };
        let x = lambda.pow(2) - &self.curve.a2 - self.x.as_ref().unwrap() - rhs.x.as_ref().unwrap();
        let y = lambda * (self.x.as_ref().unwrap() - &x) - self.y.as_ref().unwrap();
        let p = self.curve.p.clone();
        Point::new(
            self.curve,
            Some(x % p.to_bigint().unwrap()),
            Some(y % p.to_bigint().unwrap()),
        )
    }
}
