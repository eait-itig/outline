import * as React from "react";
import styled from "styled-components";

type Props = {
  children: React.ReactNode;
  sticky?: boolean;
};
const H3 = styled.h3`
  border-bottom: 1px solid ${(props) => props.theme.divider};
  margin: 12px 0;
  line-height: 1;
`;
const Underline = styled.div`
  margin-top: -1px;
  display: inline-block;
  font-weight: 500;
  font-size: 14px;
  line-height: 1.5;
  color: ${(props) => props.theme.textSecondary};
  border-bottom: 3px solid ${(props) => props.theme.textSecondary};
  padding-top: 6px;
  padding-bottom: 4px;
`;
// When sticky we need extra background coverage around the sides otherwise
// items that scroll past can "stick out" the sides of the heading
const Background = styled.div`
  // @ts-expect-error ts-migrate(2339) FIXME: Property 'sticky' does not exist on type 'ThemedSt... Remove this comment to see the full error message
  position: ${(props) => (props.sticky ? "sticky" : "relative")};
  // @ts-expect-error ts-migrate(2339) FIXME: Property 'sticky' does not exist on type 'ThemedSt... Remove this comment to see the full error message
  ${(props) => (props.sticky ? "top: 54px;" : "")}
  margin: 0 -8px;
  padding: 0 8px;
  background: ${(props) => props.theme.background};
  transition: ${(props) => props.theme.backgroundTransition};
  z-index: 1;
`;

const Subheading = ({ children, sticky, ...rest }: Props) => {
  return (
    // @ts-expect-error ts-migrate(2769) FIXME: No overload matches this call.
    <Background sticky={sticky}>
      <H3 {...rest}>
        <Underline>{children}</Underline>
      </H3>
    </Background>
  );
};

export default Subheading;