import { Drawer, styled } from '@mui/material';

export const NavDrawer = styled(Drawer)(({ theme }) => ({
  width: 240,
  flexShrink: 0,
  '& .MuiDrawer-paper': {
    width: 240,
    background: 'rgba(0, 0, 0, 0.9)',
    borderRight: '1px solid rgba(0, 255, 0, 0.2)',
    boxSizing: 'border-box',
  },
}));