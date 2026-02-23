/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 -> Apache-2.0
*/

import Image from 'next/image';

type BrandLogoProps = {
  className?: string;
};

export function BrandLogo({ className }: BrandLogoProps) {
  return (
    <Image
      src="/assets/vectorvue-logo.png"
      alt="VectorVue"
      width={196}
      height={40}
      priority
      className={className ?? 'h-10 w-auto object-contain'}
    />
  );
}
